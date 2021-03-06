package com.martin.webshop.services;

import com.martin.webshop.DAO.UserDAO;
import com.martin.webshop.models.User;
import com.martin.webshop.payload.request.SignupRequest;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    private final UserDAO userDAO;

    @Autowired
    PasswordEncoder encoder;

    public UserService(UserDAO userDAO) {
        this.userDAO = userDAO;
    }


    public User getUserByToken(String jwt) {
        return this.userDAO.getUserByJwt(jwt);
    }

    public void saveUser(User user) {
        userDAO.saveUser(user);
    }

    public void changePassword(User user, String password) {
        user.setPassword(encoder.encode(password));
        userDAO.saveUser(user);
    }

    public void createOrder(User user, String orderValue) {
        user.setMoneySpend(user.getMoneySpend() + Float.parseFloat(orderValue));
        userDAO.saveUser(user);
    }

    public Float getMoneySpend(User user) {
        return user.getMoneySpend();
    }

    public Boolean usernameAlreadyExists(SignupRequest signUpRequest) {
        return userDAO.usernameAlreadyExists(signUpRequest);
    }

    public Boolean emailAlreadyExists(SignupRequest signUpRequest) {
        return userDAO.emailAlreadyExists(signUpRequest);
    }

}
