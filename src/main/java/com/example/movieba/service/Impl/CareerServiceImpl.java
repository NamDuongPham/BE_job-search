package com.example.movieba.service.Impl;

import com.example.movieba.entities.Career;
import com.example.movieba.repository.CareerRepository;
import com.example.movieba.service.CareerService;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;


@Service
@AllArgsConstructor
public class CareerServiceImpl implements CareerService {

    private final CareerRepository careerRepository;
    @Override
    public void createCareer(String nameCareer) {
        Career career = new Career();
        career.setNameCareer(nameCareer);
        careerRepository.save(career);
    }

    @Override
    public void updateCareer(long idCareer, String nameCareer) {
        Optional<Career> career = careerRepository.findById(idCareer);
        if (career.get() != null){
            Career update = career.get();
            update.setNameCareer(nameCareer);
            careerRepository.save(update);
        }
    }

    @Override
    public void deleteCareer(long idCareer) {
        Optional<Career> career = careerRepository.findById(idCareer);
        if (career.get() != null){
            careerRepository.deleteById(idCareer);
        }
    }

    @Override
    public List<Career> getAllCareer() {
        return careerRepository.findAll().stream().map(t->{
            Career career = new Career();
            career.setCareerId(t.getCareerId());
            career.setNameCareer(t.getNameCareer());
            return career;
        }).collect(Collectors.toList());
    }
}
