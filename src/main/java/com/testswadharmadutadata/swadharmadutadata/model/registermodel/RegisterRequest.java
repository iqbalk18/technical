package com.testswadharmadutadata.swadharmadutadata.model.registermodel;

import com.testswadharmadutadata.swadharmadutadata.entity.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RegisterRequest {

    private String name;
    private String email;
    private String password;
    private String phone;
    private String numbercc;
    private Role role;
}
