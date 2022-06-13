package com.access.useraccess.controller;


import com.access.useraccess.entity.AuthenticationDto;
import com.access.useraccess.entity.User;
import com.access.useraccess.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import com.access.useraccess.service.AuthenticationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.validation.Valid;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import static org.springframework.security.web.context.HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY;

@RestController
@Slf4j
@RequestMapping("public/authentication")
public class AuthenticationController {

    @Autowired
    private AuthenticationService authenticationService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;
    private AuthenticationManager am = new SampleAuthenticationManager();

    @PostMapping
    public String login(HttpServletRequest req, @Valid @RequestBody AuthenticationDto authDto, HttpServletResponse response) {
        Authentication authentication = am.authenticate(
                new UsernamePasswordAuthenticationToken(authDto.getEmail(), authDto.getPassword()));
        SecurityContext sc = SecurityContextHolder.getContext();
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String token = this.authenticationService.login(authDto.getEmail(), authDto.getPassword());
        HttpSession session = req.getSession(true);
        session.setAttribute(SPRING_SECURITY_CONTEXT_KEY, sc);
        return authenticationService.insert(token, authDto.getEmail(), response);

    }

    @GetMapping
    public String getQualcosa() {
        return "gianfrancozola";
        //return request.getHeader("Authorization");
        //String token = tokenNotParsed.split(" ")[1];
        /*JwtUtils jwtUtils = new JwtUtils();
        return jwtUtils.validateJwtToken(token);

        return token;
         */
    }
/*
    @GetMapping()
    public Authentication getOrder() {

        return authenticationService.findById(id);
    }
*/


    class SampleAuthenticationManager implements AuthenticationManager {
        static final List<GrantedAuthority> AUTHORITIES = new ArrayList<GrantedAuthority>();

        static {
            AUTHORITIES.add(new SimpleGrantedAuthority("ROLE_USER"));
        }
        public Authentication authenticate(Authentication auth) throws AuthenticationException {
            String name = auth.getName();
            User user = userRepository.findByEmail(auth.getName()).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
            if (user.equals(null)) {
                throw new BadCredentialsException("Bad Credentials");
            }
            String password = user.getPassword();
            String passIns = (String) auth.getCredentials();
            if (passwordEncoder.matches(passIns, password)) {
                return new UsernamePasswordAuthenticationToken(auth.getName(),
                        auth.getCredentials(),AUTHORITIES);
            }
            throw new BadCredentialsException("Bad Credentials");
        }
    }

}