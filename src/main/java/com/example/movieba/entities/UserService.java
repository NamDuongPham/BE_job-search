package com.example.movieba.entities;


import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter

@Entity
public class UserService {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long idTrading;

    @OneToOne
    private User user;

    @OneToOne
    private Services services;

    @Column
    private String tradingCode;

    @Column
    private long moneyTrading;

    @Column
    private String statusTrading;

}
