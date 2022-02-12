package com.martin.webshop.DAO;

import com.martin.webshop.models.ERole;
import com.martin.webshop.models.Role;
import com.martin.webshop.repository.RoleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class RoleDAO {


    @Autowired
    RoleRepository roleRepository;

    public Role setUserRole(){
        return roleRepository.findByName(ERole.ROLE_USER)
                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
    }
}
