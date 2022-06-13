package com.access.useraccess.service;

import com.access.useraccess.entity.Authentication;
import com.access.useraccess.entity.User;
import com.access.useraccess.repository.AuthenticationRepository;
import com.access.useraccess.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.crypto.dsig.Transform;
import java.security.Key;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.ZonedDateTime;
import java.util.*;

@Slf4j
@Service
public class AuthenticationServiceImpl implements AuthenticationService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private AuthenticationRepository authenticationRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Value("${demo.app.jwtSecret}")
    private String jwtSecret;

    public String login(String email, String password) {
        User user = this.userRepository.findByEmail(email).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
        if (!this.passwordEncoder.matches(password, user.getPassword())) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Bad credentials");
        }
        ObjectNode userNode = new ObjectMapper().convertValue(user, ObjectNode.class);
        userNode.remove("password");
        Map<String, Object> claimMap = new HashMap<>(0);
        Date date = new Date();
        Date d = new Date(date.getTime());
        claimMap.put("user", userNode);
        //return JwtProvider.createJwt(email, claimMap);
        return Jwts.builder()
                .setHeaderParam("typ", "JWT")
                .setIssuer("demo-api-app")
                .setSubject(email)
                .signWith(SignatureAlgorithm.HS256, jwtSecret)
                .setIssuedAt(d)
                .setExpiration(Date.from(ZonedDateTime.now().plusMinutes(5).toInstant()))
                .compact();
    }

    @Override
    public String insert(String token, String email, HttpServletResponse response) {
        User user = this.userRepository.findByEmail(email).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
        Authentication auth = new Authentication();
        auth.setId_user(user.getId());
        auth.setToken(token);
        Optional<Authentication> result = Optional.ofNullable(findIfIdUserIsCreated(user.getId()));
        response.setHeader("Authorization", "Bearer " + token);
        if (result.isPresent()) {
            Authentication authDB = result.get();
            authDB.setToken(token);
            authenticationRepository.save(authDB);
            return "Token updated";
        } else {
            authenticationRepository.save(auth);
            return "Token created";
        }
    }

    @Override
    public Authentication findIfIdUserIsCreated(Long id_user) {
        Iterable<Authentication> result = authenticationRepository.findAll();
        for(Authentication a : result){
                if (a.getId_user().equals(id_user)) {
                    return a;
                }
        }
        return null;
    }

    @Override
    public String findTokenFromIdUser (Long id_user) {
        Iterable<Authentication> result = authenticationRepository.findAll();
        for(Authentication a : result){
            if (a.getId_user().equals(id_user)) {
                return a.getToken();
            }
        }
        return null;
    }
}