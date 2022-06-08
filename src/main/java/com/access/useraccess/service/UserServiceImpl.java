package com.access.useraccess.service;

import com.access.useraccess.entity.User;
import com.access.useraccess.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class UserServiceImpl implements UserService {
    private final UserRepository repository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public UserServiceImpl(UserRepository repository) {
        this.repository = repository;
    }

    @Override
    public String insert(User user) {
        Iterable<User> result = repository.findAll();
        for(User u : result){
            if (user.getEmail()!= null) {
                if (u.getEmail().equals(user.getEmail())) {
                    return "Email already registered";
                }
            } else {
                return "Email: null";
            }
        }
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        repository.save(user);
        return "Added a user";
    }

    @Override
    public Long findIdByEmail(String email) {
        Iterable<User> result = repository.findAll();
        for(User c : result){
            if (c.getEmail()!= null) {
                if (c.getEmail().equals(email)) {
                    return c.getId();
                }
            }
        }
        return null;
    }
}
