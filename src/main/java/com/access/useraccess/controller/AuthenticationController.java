package com.access.useraccess.controller;


import com.access.useraccess.entity.AuthenticationDto;
import com.access.useraccess.service.AuthenticationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

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