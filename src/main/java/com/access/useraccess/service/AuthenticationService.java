package com.access.useraccess.service;

import com.access.useraccess.entity.Authentication;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public interface AuthenticationService {
    String login(String email, String password);

    String insert (String token, String email, HttpServletResponse response);

    Authentication findIfIdUserIsCreated(Long id_user);

    String findTokenFromIdUser (Long id_user);
}
