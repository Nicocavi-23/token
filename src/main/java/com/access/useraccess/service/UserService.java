package com.access.useraccess.service;

import com.access.useraccess.entity.User;

public interface UserService {

    // post for registration
    String insert(User user);

    Long findIdByEmail(String email);

}
