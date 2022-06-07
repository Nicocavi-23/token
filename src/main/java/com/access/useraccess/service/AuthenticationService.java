package com.access.useraccess.service;

public interface AuthenticationService {
    String login(String email, String password);

    String insert (String token, String email);
}
