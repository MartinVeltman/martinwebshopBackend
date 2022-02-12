package com.martin.webshop.controllers;

import com.martin.webshop.models.Item;
import com.martin.webshop.payload.response.MessageResponse;
import com.martin.webshop.security.services.ItemService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/v1")
public class ItemController {

    @Autowired
    ItemService itemService;

    @PostMapping("/admin/createItem")
    public ResponseEntity<?> createItem(@RequestBody Item item) {
        itemService.createItem(item);
        return MessageResponse.generateResponse("Item succesvol toegevoegd", HttpStatus.OK, null);
    }

    @GetMapping("/getItems")
    @ResponseBody
    public Object getItems() {
        try {
            return itemService.getAllItems();
        } catch (Exception e) {
            return MessageResponse.generateResponse("An error has occurred: " + e, HttpStatus.BAD_REQUEST, null);
        }
    }

}
