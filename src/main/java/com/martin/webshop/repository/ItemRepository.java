package com.martin.webshop.repository;

import com.martin.webshop.models.Item;
import com.martin.webshop.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ItemRepository extends JpaRepository<Item, Long> {
}
