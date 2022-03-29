package com.martin.webshop.services;

import com.martin.webshop.DAO.RoleDAO;
import com.martin.webshop.models.Role;
import org.springframework.stereotype.Service;

@Service
public class RoleService {

    private final RoleDAO roleDAO;

    public RoleService(RoleDAO roleDAO) {
        this.roleDAO = roleDAO;
    }

    public Role setUserRole() {
        return roleDAO.setUserRole();
    }
}
