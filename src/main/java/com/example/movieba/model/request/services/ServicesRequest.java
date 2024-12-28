package com.example.movieba.model.request.services;


import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class ServicesRequest {
    private String nameServices;
    private String describeService;
    private long priceService;
    private long time;
    private long numberNews;
}
