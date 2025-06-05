package com.thirumal.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

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
    public JwkRequest receiveClientKey(@RequestBody JwkRequest jwkeRequest) throws Exception {
        return hybridCryptographyService.receiveClientKey(jwkeRequest);
    }
}
