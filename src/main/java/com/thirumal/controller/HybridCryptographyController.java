package com.thirumal.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import com.thirumal.service.HybridCryptographyService;

@Controller
@RequestMapping("/hybrid-cryptography")
public class HybridCryptographyController {
    
    private final HybridCryptographyService hybridCryptographyService;
    public HybridCryptographyController(HybridCryptographyService hybridCryptographyService) {
        this.hybridCryptographyService = hybridCryptographyService;
    }

    @GetMapping("/handshake")
    public String initiateHandShake(Model model)  {
        model.addAttribute("initialHandshake", hybridCryptographyService.initiateHandShake());
        return "HybridCryptography";
    }
}
