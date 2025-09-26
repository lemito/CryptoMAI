#include <iostream>
#include <cstddef>
#include <vector>

enum class bitIndexingRule : int8_t {
	LSB_to_MSB, // младший->старший
	MSB_to_LSB  // старший->младший
};

std::vector <std::byte> permutation(const std::vector<std::byte>& in, const auto permutationRule, bitIndexingRule rule = bitIndexingRule::LSB_to_MSB, int8_t startBitNumer = 0) {
	if (startBitNumer < 0 || startBitNumer > 1) {
		throw std::runtime_error("Неправильный аргумент старта");
	}
	std::vector<std::byte> res;
	res.reserve(in.size());
	return res;
}

int main() {
	return 0;
}