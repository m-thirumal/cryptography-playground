package com.thirumal.controller;

import java.util.Arrays;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

import com.thirumal.model.EncryptedMessage;
import com.thirumal.model.JwkRequest;
import com.thirumal.service.HybridCryptographyService;

@RestController
@RequestMapping("/hybrid-cryptography")
public class HybridCryptographyController {
    
    private final HybridCryptographyService hybridCryptographyService;

    public HybridCryptographyController(HybridCryptographyService hybridCryptographyService) {
        this.hybridCryptographyService = hybridCryptographyService;
    }

    @GetMapping("/handshake")
    public ModelAndView initiateHandShake()  {
        return new ModelAndView("HybridCryptography");
    }

    @PostMapping("/client-public")
    public JwkRequest receiveClientKey(@RequestBody JwkRequest jwkeRequest, @RequestHeader("Cookie") String cookieHeader) throws Exception {
        String jsessionId = extractJsessionId(cookieHeader);
        if (jsessionId == null) {
            throw new IllegalArgumentException("JSESSIONID cookie not found");
        }
        return hybridCryptographyService.receiveClientKey(jsessionId, jwkeRequest);
    }

    @PostMapping("/decrypt-message")
    public ResponseEntity<String> decryptMessage(@RequestBody EncryptedMessage encryptedMessage, @RequestHeader("Cookie") String cookieHeader) throws Exception {
        String jsessionId = extractJsessionId(cookieHeader);
        if (jsessionId == null) {
            throw new IllegalArgumentException("JSESSIONID cookie not found");
        }
        jsessionId = extractJsessionId(cookieHeader);
        String decryptedMessage = hybridCryptographyService.decryptMessage(jsessionId, encryptedMessage);
        System.out.println("Decrypted message: " + decryptedMessage);
        return ResponseEntity.ok(decryptedMessage);
    }

    private String extractJsessionId(String cookieHeader) {
        if (cookieHeader == null) return null;
        return Arrays.stream(cookieHeader.split(";"))
                .map(String::trim)
                .filter(c -> c.startsWith("JSESSIONID="))
                .findFirst()
                .map(c -> c.substring("JSESSIONID=".length()))
                .orElse(null);
    }

}
