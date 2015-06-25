import Promise from 'dojo-core/Promise';
import { Data, SimpleKey, Key, Signer, SignFunction } from '../../crypto';
import { ByteBuffer, Codec, utf8 } from 'dojo-core/encoding';

/**
 * A mapping of crypto algorithm names to their webcrypto equalivalents
 */
const ALGORITHMS = {
	hmac: 'hmac'
};

const HASH: { [key: string]: string } = {
	sha256: 'sha-256',
	'sha-256': 'sha-256',
	sha1: 'sha-1',
	'sha-1': 'sha-1'
};

const DEFAULT_CODEC = utf8;
const resolvedPromise = Promise.resolve();
const global = window;

/**
 *
 * @param algorithm
 * @param key
 * @param data
 * @return {any}
 */
function sign(algorithm: string, key: Key | Promise<Key>, data: Data, codec: Codec): Promise<ByteBuffer> {
	return Promise.resolve(key).then(produceCryptoKey.bind(null, algorithm)).then(function (key: CryptoKey) {
		return global.crypto.subtle.sign(algorithm, key, dataToArrayBufferView(data, codec))
			.then(function(signature: ArrayBuffer) {
				return new Uint8Array(signature);
			});
	});
}

function dataToArrayBufferView(data: Data, codec: Codec): Uint8Array {
	if (typeof data === 'string') {
		return new Uint8Array(codec.encode(data));
	}

	if (!(data instanceof Uint8Array)) {
		return new Uint8Array(<number[]> data);
	}

	return <Uint8Array> data;
}

function produceCryptoKey(algorithm: string, key: Key): CryptoKey | Promise<CryptoKey> {
	if (key instanceof CryptoKey) {
		return key;
	}

	var hash: string = (<SimpleKey> key).algorithm;
	var algorithmAndHash = {
		name: algorithm,
		hash: { name: HASH[hash] || hash }
	};

	var input: ArrayBufferView = new Uint8Array(utf8.encode(<string> (<SimpleKey> key).data));
	return global.crypto.subtle.importKey('raw', input, algorithmAndHash, false, ['sign','verify'])
}

function concatUint8Arrays(left: Uint8Array, right: Uint8Array) {
	var result = new Uint8Array(left.length + right.length);
	result.set(left, 0);
	result.set(right, left.length);
	return result;
}

class WebSigner<T extends Data> implements Signer<T> {
	constructor(algorithm: string, key: Key | Promise<Key>, codec: Codec) {
		this._codec = codec;
		this._algorithm = algorithm;
		this._key = key;
		this.start(); // TODO according to tests calling start isn't required
		Object.defineProperty(this, 'signature', {
			value: new Promise((resolve, reject) => {
				Object.defineProperty(this, '_resolve', { value: resolve });
				Object.defineProperty(this, '_reject', { value: reject });
			})
		});
	}

	private _key: Key | Promise<Key>;
	private _algorithm: string;
	private _codec: Codec;
	private _buffer: Uint8Array;
	private _resolve: (value: any) => void;
	private _reject: (reason: Error) => void;

	signature: Promise<ByteBuffer>;

	abort(reason:any):Promise<void> {
		this._reject(reason);
		return resolvedPromise;
	}

	start(error?:(p1:Error)=>void):Promise<void> {
		this._buffer = new Uint8Array(0);
		return resolvedPromise;
	}

	write(chunk:T):Promise<void> {
		var result = resolvedPromise;
		try {
			this._buffer = concatUint8Arrays(this._buffer, dataToArrayBufferView(chunk, this._codec));
		}
		catch (e) {
			result = Promise.reject(e);
		}

		return result;
	}

	close():Promise<void> {
		try {
			this._resolve(sign(this._algorithm, this._key, this._buffer, this._codec));
			this._buffer = null;
		}
		catch(e) {
			this._reject(e);
		}
		return resolvedPromise;
	}
}

export default function getSign(algorithm: string): SignFunction {
	algorithm = algorithm.toLowerCase();

	if (!(algorithm in ALGORITHMS)) {
		throw new Error('invalid algorithm; available algorithms are [ \'' + Object.keys(ALGORITHMS).join('\', \'') + '\' ]');
	}

	let signFunction = <SignFunction> function (key: Key | Promise<Key>, data: Data, codec: Codec = DEFAULT_CODEC): Promise<ByteBuffer> {
		return sign(algorithm, key, data, codec);
	};
	signFunction.create = function<T extends Data> (key: Key | Promise<Key>, codec: Codec = DEFAULT_CODEC): Signer<T> {
		return new WebSigner<T>(algorithm, key, codec);
	};
	signFunction.algorithm = algorithm;

	return signFunction;
}
