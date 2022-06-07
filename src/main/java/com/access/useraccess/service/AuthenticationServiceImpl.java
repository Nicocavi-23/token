package com.access.useraccess.service;

import com.access.useraccess.entity.Authentication;
import com.access.useraccess.entity.User;
import com.access.useraccess.repository.AuthenticationRepository;
import com.access.useraccess.repository.UserRepository;
import com.access.useraccess.security.JwtProvider;
import com.auth0.jwt.JWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@Service
public class AuthenticationServiceImpl implements AuthenticationService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private AuthenticationRepository authenticationRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public String login(String email, String password) {
        User user = this.userRepository.findByEmail(email).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
        if (!this.passwordEncoder.matches(password, user.getPassword())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Bad credentials");
        }
        ObjectNode userNode = new ObjectMapper().convertValue(user, ObjectNode.class);
        userNode.remove("password");
        Map<String, Object> claimMap = new HashMap<>(0);
        claimMap.put("user", userNode);
        return JwtProvider.createJwt(email, claimMap);
    }

    @Override
    public String insert(String token, String email) {
        User user = this.userRepository.findByEmail(email).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
        Authentication auth = new Authentication();
        log.debug(token);
        auth.setId_user(user.getId());
        auth.setToken(token);
        String[] chunks = token.split("\\.");
        Base64.Decoder decoder = Base64.getUrlDecoder();
        String header = new String(decoder.decode(chunks[0]));
        String payload = new String(decoder.decode(chunks[1]));
        String signature = new String(decoder.decode(chunks[2]));
        log.debug(payload);
        authenticationRepository.save(auth);
        return "Authenticated";
    }
}