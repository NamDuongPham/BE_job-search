package com.example.movieba.service;

import com.example.movieba.entities.Location;

import java.util.List;

public interface LocationService {
    void createLocation(String nameLocation);
    void updateLocation(long idLocation, String nameLocation);
    void deleteLocation(long idLocation);

    List<Location> getAll();
}
