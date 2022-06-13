package com.access.useraccess.controller;

import com.access.useraccess.entity.User;
import com.access.useraccess.service.AuthenticationService;
import com.access.useraccess.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import javax.validation.Valid;
import java.util.Base64;
import java.util.Date;
import java.util.List;

@RestController
@Slf4j
public class UserController {

    private final UserService userService;

    private final AuthenticationService authenticationService;

    public UserController(UserService userService, AuthenticationService authenticationService) {
        this.userService = userService;
        this.authenticationService = authenticationService;
    }

    @PostMapping("/signup")
    public String insert(@Valid @RequestBody User user) {
        return userService.insert(user);
    }

    /* Quando ancora eravamo vecchie glorie
    @GetMapping("/orders/{email}")
    public Object getSomething(@PathVariable String email) {


        //find id from email in users
        Long id = userService.findIdByEmail(email);
                //find token from id_users in credentials
        String token = String.valueOf(authenticationService.findTokenFromIdUser(id));
                //check exp token valid
        String[] chunks = token.split("\\.");
        Base64.Decoder decoder = Base64.getUrlDecoder();
        String payload = new String(decoder.decode(chunks[1]));
        chunks = payload.split(",");
        chunks = chunks[1].split(":");
        Long exp = Long.valueOf(chunks[1]);
        Date date = new Date();
        Long d = date.getTime()/1000;
        if (exp < d){
            return "Token not valid";
        }
                //ESECUZIONE API NICO REPO
        String uri = "http://localhost:8084/api/customer/orders/" + id;
        RestTemplate restTemplate = new RestTemplate();
        Object result = restTemplate.getForObject(uri, Object.class);
        return result;
    }*/
}
