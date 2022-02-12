package com.martin.webshop.security.services;

import com.martin.webshop.DAO.UserDAO;
import com.martin.webshop.models.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    private final UserDAO userDAO;

    public UserService(UserDAO userDAO) {
        this.userDAO = userDAO;
    }


    public User getUserByToken(String jwt) {
        return this.userDAO.getUserByJwt(jwt);
    }
}
