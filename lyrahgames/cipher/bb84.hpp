#pragma once
#include <bit>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <random>

namespace lyrahgames::cipher {

namespace bb84 {

// We can only simulate qubits.
// For the BB84 protocol, there are only four different states to encode.
// Hence, no actual qubit implementation based on C^2 is used.
// To store a bit, we need two bits.
// As a consequence for this simulation, a qubyte should store 16 bit.
// The first 8 bits store the basis and the second half the actual information.
// Remember, in reality, qubits can only be observed by being measured.
using qubyte = uint16_t;

void randomize(uint8_t* data, size_t size) {
  // Use truely random number generator.
  std::random_device rng{};
  for (size_t i = 0; i < size; ++i) data[i] = rng();
}

void encode(qubyte* qubits,
            const uint8_t* basis,
            const uint8_t* data,
            size_t size) {
  for (size_t i = 0; i < size; ++i)
    qubits[i] = (uint16_t(basis[i]) << 8) | data[i];
}

void measure(uint8_t* data,
             const qubyte* qubits,
             const uint8_t* basis,
             size_t size) {
  std::random_device rng{};
  for (size_t i = 0; i < size; ++i) {
    uint8_t qubyte_basis = qubits[i] >> 8;
    // every '1' bit means random measurement
    // because different basis were used.
    auto mask = qubyte_basis ^ basis[i];
    data[i] = ((~mask) & uint8_t(qubits[i])) | (mask & uint8_t(rng()));
  }
}

void compare(uint8_t* data,
             const uint8_t* basis1,
             const uint8_t* basis2,
             size_t size) {
  using namespace std;
  size_t bits = 0;
  size_t byte = 0;

  for (size_t i = 0; i < size; ++i) {
    uint8_t x = data[i];
    data[i] = 0;
    uint8_t mask = ~(basis1[i] ^ basis2[i]);
    while (mask) {
      if (mask & 0b1) {
        data[byte] |= ((x & 0b1) << bits);
        ++bits;
        if (bits >= 8) {
          bits = 0;
          ++byte;
        }
      }
      mask >>= 1;
      x >>= 1;
    }
  }
}

}  // namespace bb84

}  // namespace lyrahgames::cipher
