package com.example.movieba.service.Impl;

import com.example.movieba.entities.Location;
import com.example.movieba.repository.LocationRepository;
import com.example.movieba.service.LocationService;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@AllArgsConstructor
public class LocationServiceImpl implements LocationService {
    private final LocationRepository locationRepository;
    @Override
    public void createLocation(String nameLocation) {
        Location location = new Location();
        location.setNameLocation(nameLocation);
        locationRepository.save(location);
    }

    @Override
    public void updateLocation(long idLocation, String nameLocation) {
        Optional<Location> findLocation = locationRepository.findById(idLocation);
        if (findLocation.get() != null){
            Location locations = findLocation.get();
            locations.setNameLocation(nameLocation);
            locationRepository.save(locations);
        }
    }

    @Override
    public void deleteLocation(long idLocation) {
        Optional<Location> findLocation = locationRepository.findById(idLocation);
        if (findLocation.get() != null){
            locationRepository.deleteById(idLocation);
        }
    }

    @Override
    public List<Location> getAll() {
        return locationRepository.findAll().stream().map(t->{
            Location location = new Location();
            location.setIdLocation(t.getIdLocation());
            location.setNameLocation(t.getNameLocation());
            return location;
        }).collect(Collectors.toList());
    }
}
