package com.access.useraccess.service;

import com.access.useraccess.entity.Authentication;

public interface AuthenticationService {
    String login(String email, String password);

    String insert (String token, String email);

    Authentication findIfIdUserIsCreated(Long id_user);

    String findTokenFromIdUser (Long id_user);
}
