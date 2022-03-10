#include <doctest/doctest.h>
//
#include <bit>
#include <bitset>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <random>

using namespace std;

SCENARIO("BB84 8-bit Key Example") {
  random_device rng{};

  // Alice
  uint8_t base_key1 = rng();
  uint8_t basis1 = rng();
  uint16_t qubits = (uint16_t(basis1) << 8) | base_key1;

  cout << endl;
  cout << bitset<8>{base_key1} << '\n' << bitset<8>{basis1} << '\n' << endl;

  // Bob
  uint8_t basis2 = rng();
  uint8_t measure_mask = (uint8_t(qubits >> 8) ^ basis2);
  uint8_t base_key2 =
      (~measure_mask & uint8_t(qubits)) | (measure_mask & uint8_t(rng()));

  cout << bitset<8>{base_key2} << '\n' << bitset<8>{basis2} << '\n' << endl;

  uint8_t delete_mask = basis1 ^ basis2;
  uint8_t key1 = 0;
  uint8_t key2 = 0;
  uint8_t bits = 0;
  while (delete_mask) {
    if (!(delete_mask & 0b1)) {
      key1 |= (base_key1 & 0b1) << bits;
      key2 |= (base_key2 & 0b1) << bits;
      ++bits;
    }
    base_key1 >>= 1;
    base_key2 >>= 1;
    delete_mask >>= 1;
  }

  cout << "bits = " << int(bits) << '\n';
  cout << bitset<8>{key1} << '\n' << bitset<8>{key2} << '\n' << endl;
}
