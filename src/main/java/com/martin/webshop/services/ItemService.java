package com.martin.webshop.services;


import com.martin.webshop.DAO.ItemDAO;
import com.martin.webshop.models.Item;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class ItemService {

    private final ItemDAO itemDAO;

    public ItemService(ItemDAO itemDAO) {
        this.itemDAO = itemDAO;
    }

    public List<Item> getAllItems() {
        return itemDAO.getAllItems();
    }

    public void createItem(Item item) {
        item.setQty(1);
        itemDAO.createItem(item);
    }
}
