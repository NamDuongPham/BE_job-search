package com.example.movieba.entities;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter

@Entity
public class Services {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private long idService;

    @Column
    private String nameServices;

    @Column(columnDefinition = "text")
    private String describeService;

    @Column
    private long priceService;

    @Column
    private long numberNews;

    @Column(columnDefinition = "BIGINT default 0")
    private long time;

//    @OneToOne(mappedBy = "serviceCom")
//    private CompanyServices companyServices;

}
