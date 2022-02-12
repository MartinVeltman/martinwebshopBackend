package com.martin.webshop.DAO;

import com.martin.webshop.models.Item;
import com.martin.webshop.repository.ItemRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class ItemDAO {

    @Autowired
    ItemRepository itemRepository;

    public List<Item> getAllItems() {
        return this.itemRepository.findAll();
    }

    public void createItem(Item item) {
        itemRepository.save(item);
    }
}
