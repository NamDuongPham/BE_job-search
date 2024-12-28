package com.example.movieba.service;

import com.example.movieba.entities.Services;
import com.example.movieba.model.request.services.ServicesRequest;

import java.util.List;

public interface ServicesRe {

    void createServices(ServicesRequest servicesRequest);

    void updateServices(long idService, ServicesRequest servicesRequest);

    void deleteServices(long idService);

    List<Services> getAllServices();
}
