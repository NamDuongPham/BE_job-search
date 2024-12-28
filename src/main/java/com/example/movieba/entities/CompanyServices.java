package com.example.movieba.entities;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;


import java.util.Date;


@Setter
@Getter

@Entity
public class CompanyServices {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long idComService;

    @Column
    private Date timeStart;

    @Column
    private Date timeEnd;

    @OneToOne
    @JoinColumn(name = "id_company")
    private Company companySer;

    @OneToOne
    @JoinColumn(name = "id_service")
    private Services serviceCom;
}
