function merge(left: Array<any>, right: Array<any>, comparison: Function): Array<any> {
  const result = [];
  while (left.length > 0 && right.length > 0) {
    if (comparison(left[0], right[0]) <= 0) {
      result.push(left.shift());
    } else {
      result.push(right.shift());
    }
  }
  while (left.length > 0) {
    result.push(left.shift());
  }
  while (right.length > 0) {
    result.push(right.shift());
  }
  return result;
}

export default function mergeSort(array: Array<any>, comparison: Function): Array<any> {
  if (array.length < 2) {
    return array;
  }
  const middle = Math.ceil(array.length / 2);
  return merge(mergeSort(array.slice(0, middle), comparison), mergeSort(array.slice(middle), comparison), comparison);
}
