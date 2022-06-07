package com.access.useraccess.controller;

import com.access.useraccess.entity.User;
import com.access.useraccess.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@RestController
@RequestMapping("/signup")
@Slf4j
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping("")
    public String insert(@Valid @RequestBody User user) {
        return userService.insert(user);
    }

}
