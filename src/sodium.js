let sodiumPromise;

// Pin the wrapper and wait for its WASM/JavaScript crypto implementation.
export async function loadSodium() {
  sodiumPromise ||= import('libsodium-wrappers-sumo').then(async module => {
    const sodium = module.default;
    await sodium.ready;
    return sodium;
  }).catch(error => {
    sodiumPromise = undefined;
    throw new Error('The encryption library could not be loaded. Please try again.', { cause: error });
  });
  return sodiumPromise;
}

