package com.access.useraccess.controller;


import com.access.useraccess.entity.AuthenticationDto;
import com.access.useraccess.service.AuthenticationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.util.List;

@RestController
@RequestMapping("public/authentication")
public class AuthenticationController {

    @Autowired
    private AuthenticationService authenticationService;

    @PostMapping
    public String login(@RequestBody AuthenticationDto authDto) {
        String token = this.authenticationService.login(authDto.getEmail(), authDto.getPassword());
        return authenticationService.insert(token, authDto.getEmail());
    }


}