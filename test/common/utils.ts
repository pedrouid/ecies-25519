import { arrayToHex } from 'enc-utils';

export function compare(arr1: Uint8Array, arr2: Uint8Array) {
  return arrayToHex(arr1) === arrayToHex(arr2);
}

export async function prettyPrint(name: string, obj: any) {
  const displayObject: any = {};
  Object.keys(obj).forEach((key: string) => {
    const value =
      obj[key]?.name === 'Uint8Array' ? arrayToHex(obj[key]) : obj[key];
    displayObject[key] = value;
  });
  console.log(name, JSON.stringify(displayObject, null, 2));
}
