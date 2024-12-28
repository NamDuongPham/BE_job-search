package com.example.movieba.service;

import com.example.movieba.entities.Career;

import java.util.List;

public interface CareerService {
    void createCareer(String nameCareer);
    void updateCareer(long idCareer, String nameCareer);
    void deleteCareer(long idCareer);

    List<Career> getAllCareer();
}
