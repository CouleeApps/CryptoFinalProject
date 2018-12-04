#include "blum_goldwasser.h"
#include <utility>

//Conversion functions that would have been way cleaner in a CharStream :^)
std::vector<uint8_t> vla_vec2vector(std::vector<uint8_t> &&vec) {
	std::vector<uint8_t> bytes;
	auto size = vec.size();

	bytes.push_back(static_cast<uint8_t>(size & 0xFF));
	bytes.push_back(static_cast<uint8_t>((size >> 8) & 0xFF));
	bytes.push_back(static_cast<uint8_t>((size >> 16) & 0xFF));
	bytes.push_back(static_cast<uint8_t>((size >> 24) & 0xFF));

	std::move(vec.begin(), vec.end(), std::back_inserter(bytes));
	return bytes;
}

std::vector<uint8_t> bg_enc2vector(const std::vector<mpz> &msg, const mpz &Nm) {
	std::vector<uint8_t> bytes;

	std::vector<uint8_t> Nm_vec = vla_vec2vector(mpz2vector(Nm));
	std::move(Nm_vec.begin(), Nm_vec.end(), std::back_inserter(bytes));

	for (const mpz &b : msg) {
		std::vector<uint8_t> b_vec = vla_vec2vector(mpz2vector(b));
		std::move(b_vec.begin(), b_vec.end(), std::back_inserter(bytes));
	}

	return bytes;
}

mpz vector_eat_vla_mpz(std::vector<uint8_t> &vec) {
	size_t size = 0;
	size |= (vec.front());       vec.erase(vec.begin());
	size |= (vec.front()) << 8;  vec.erase(vec.begin());
	size |= (vec.front()) << 16; vec.erase(vec.begin());
	size |= (vec.front()) << 24; vec.erase(vec.begin());

	std::vector<uint8_t> bytes;
	std::move(vec.begin(), vec.begin() + size, std::back_inserter(bytes));
	vec.erase(vec.begin(), vec.begin() + size); //Because somehow move doesn't do this

	return vector2mpz(bytes);
}

void vector2bg_enc(std::vector<uint8_t> msg, std::vector<mpz> &c, mpz &Nm) {
	Nm = vector_eat_vla_mpz(msg);

	while (!msg.empty()) {
		c.push_back(vector_eat_vla_mpz(msg));
	}
}

std::vector<uint8_t> bg_encrypt(const std::vector<uint8_t> &vmsg, const bg_pubkey &key) {
	mpz m = vector2mpz(vmsg);
	mpz Nm = vmsg.size() * 8; //Assuming 8 bits per byte like a champion

	mpz n = array2mpz(key.n, BG_KEY_LENGTH * 2);
	mpz k = (mpz)mpz_log2(n);
	mpz h = (mpz)mpz_log2(k);
	mpz t_mpz;
	mpz_cdiv_q(t_mpz.get_mpz_t(), Nm.get_mpz_t(), h.get_mpz_t());
	unsigned long t = t_mpz.get_ui();

	//Generate random r, x_0 = r^2 mod N
	mpz r;
	{
		FILE *devrandom = fopen("/dev/urandom", "rb");
		uint8_t randoms[16];
		fread(randoms, sizeof(uint8_t), 16, devrandom);
		fclose(devrandom);

		mpz random = array2mpz(randoms, 16);
		gmp_randstate_t rs;
		gmp_randinit_default(rs);
		gmp_randseed(rs, random.get_mpz_t());
		mpz_urandomm(r.get_mpz_t(), rs, n.get_mpz_t());
		gmp_randclear(rs);
	}

	mpz x_0 = modpow(r, 2, n);

	//Lowest h bits
	mpz h_mask;
	for (mp_bitcnt_t i = 0; i < h; i ++) {
		mpz_setbit(h_mask.get_mpz_t(), i);
	}

	std::vector<mpz> c;
	std::vector<mpz> x;
	x.push_back(x_0);

	for (uint64_t i = 1; i <= t; i ++) {
		mpz x_i = (x[i - 1] * x[i - 1]) % n;
		x.push_back(x_i);

		mpz p_i = x_i & h_mask;
		mpz shift = mpz{(unsigned int)(t - i)} * h;
		mpz m_i = (m >> shift.get_ui()) & h_mask;
		mpz c_i = p_i ^ m_i;

		c.push_back(c_i);
	}
	mpz x_t_plus_1 = (x[t] * x[t]) % n;
	c.push_back(x_t_plus_1);

	return bg_enc2vector(c, Nm);
}

std::pair<mpz, mpz> egcd(mpz a, mpz b) {
	mpz a0 = 1, a1 = 0, b0 = 0, b1 = 1, q;

	while (true) {
		q = a / b;
		a = a % b;
		a0 = a0 - q * a1;
		b0 = b0 - q * b1;
		if (a == 0) {
			return std::pair<mpz, mpz>{a1, b1};
		}
		q = b / a;
		b = b % a;
		a1 = a1 - q * a0;
		b1 = b1 - q * b0;
		if (b == 0) {
			return std::pair<mpz, mpz>{a0, b0};
		}
	}
}

std::vector<uint8_t> bg_decrypt(const std::vector<uint8_t> &msg, const bg_privkey &key) {
	mpz Nm;
	std::vector<mpz> c;

	vector2bg_enc(msg, c, Nm);

	mpz p = array2mpz(key.p, BG_KEY_LENGTH);
	mpz q = array2mpz(key.q, BG_KEY_LENGTH);

	std::pair<mpz, mpz> ab = egcd(p, q);
	mpz a = ab.first;
	mpz b = ab.second;

	mpz n = p * q;
	mpz k = (mpz)mpz_log2(n);
	mpz h = (mpz)mpz_log2(k);
	mpz t_mpz;
	mpz_cdiv_q(t_mpz.get_mpz_t(), Nm.get_mpz_t(), h.get_mpz_t());
	unsigned long t = t_mpz.get_ui();

	//Lowest h bits
	mpz h_mask;
	for (mp_bitcnt_t i = 0; i < h; i ++) {
		mpz_setbit(h_mask.get_mpz_t(), i);
	}

	mpz d_1 = modpow((p + 1)/4, t + 1, p - 1);
	mpz d_2 = modpow((q + 1)/4, t + 1, q - 1);

	mpz x_t_plus_1 = c[t];
	mpz u = modpow(x_t_plus_1, d_1, p);
	mpz v = modpow(x_t_plus_1, d_2, q);

	mpz x_0 = ((mpz)v * a * (mpz)p + (mpz)u * b * (mpz)q) % n;

	mpz m;
	std::vector<mpz> x;
	x.push_back(x_0);

	for (uint64_t i = 1; i <= t; i ++) {
		mpz x_i = (x[i - 1] * x[i - 1]) % n;
		x.push_back(x_i);

		mpz p_i = x_i & h_mask;
		mpz c_i = c[i - 1];
		mpz m_i = (p_i ^ c_i) & h_mask;

		mpz shift = mpz{(unsigned int)(t - i)} * h;
		m |= m_i << shift.get_ui();
	}

	return mpz2vector(m);
}
