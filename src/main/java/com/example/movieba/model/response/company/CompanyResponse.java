package com.example.movieba.model.response.company;


import com.example.movieba.entities.User;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class CompanyResponse {
    private long idCompany;
    private String nameCompany;
    private String addressCompany;
    private String listNews;
    private long moneyInAccount;
    private String userName;
    private String imageCompany;
    private long countNews;
}
