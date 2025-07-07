package com.thirumal.service;

import org.junit.jupiter.api.Test;

class HybridCryptographyServiceTest {
	
	@Test
	void test() throws Exception {
		String data = "hcFx+t9P1zx++fdk9HA3R5SBF8oi23D7sYErY5wCnT/gOsGqQi/+Z89F6maH4YhU9/7Z8mSBjhP1KnPTKKqY6stdM2AC+lisMN142Mh415U=";
		String iv = "abcdef0123456789";
		String key = "0123456789abcdef"; // 16-byte key (128-bit)
	
		String originalText = HybridCryptographyService.decrypt(data, key, iv);
		System.out.println("Decrypted text: " + originalText);
	}

}
