/**
 * 
 */
package com.thirumal.model;

import java.security.KeyPair;
import java.security.PublicKey;

import javax.crypto.SecretKey;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

/**
 * 
 */
@AllArgsConstructor
@Getter@Setter
@ToString@Builder
public class SessionKeyContext {
	
    private PublicKey clientPublicKey;
    private KeyPair serverKeyPair;
    private SecretKey sharedSecret;

}
