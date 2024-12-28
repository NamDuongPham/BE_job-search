package com.example.movieba.service.Impl;

import com.example.movieba.entities.*;
import com.example.movieba.mapper.CvMapper;
import com.example.movieba.model.request.json.DataSave;
import com.example.movieba.model.response.cv.CvInNewResponse;
import com.example.movieba.model.response.cv.CvRequest;
import com.example.movieba.model.response.cv.CvResponse;
import com.example.movieba.model.response.news.NewHasCvResponse;
import com.example.movieba.repository.*;
import com.example.movieba.service.CvService;
import com.example.movieba.service.FileStorageService;
import com.google.gson.Gson;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import lombok.AllArgsConstructor;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;

@Service
@AllArgsConstructor
public class CvServiceImpl implements CvService {
    private final CvRepository cvRepository;
    private final NewsRepository newsRepository;
    private final FileStorageService fileStorageService;
    private final UserRepository userRepository;

    private final CvMapper cvMapper;

    private final LocationRepository locationRepository;
    private final CareerRepository careerRepository;


    @Override
    public int getTotalCvs() {
        return cvRepository.findAll().size();
    }

    @Override
    public List<Cv> getAllCvs() {
        return cvRepository.findAll().stream().map(t -> {
            Cv cv = new Cv();
            cv.setIdCv(t.getIdCv());
            cv.setNameFile(t.getNameFile());
            cv.setCreateTime(t.getCreateTime());
            cv.setPathFile(t.getPathFile());
            cv.setSecurity(t.getSecurity());
            return cv;
        }).collect(Collectors.toList());
    }

    @Override
    public List<CvInNewResponse> getByCvsByIdNew(long idNew) {
        Optional<News> findNew = newsRepository.findById(idNew);
        if (findNew.get() != null) {

            List<CvInNewResponse> listCvs = Arrays.stream(findNew.get().getListCV().split(";")).filter(s->!s.isBlank()).map(t->{
                Gson gson = new Gson();
                DataSave dataSave = gson.fromJson(t,DataSave.class);
                Optional<Cv> findCv = cvRepository.findById(dataSave.getId());
                CvInNewResponse cvs = new CvInNewResponse();
                cvs.setContent(dataSave.getContent());
                cvs.setStatus(dataSave.getStatus());
                cvs.setIdCv(dataSave.getId());
                cvs.setNameCareer(findCv.get().getCareerCv().getNameCareer());
                cvs.setNameLocation(findCv.get().getLocationCv().getNameLocation());
                cvs.setNameCv(findCv.get().getNameFile());
                return cvs;

            }).collect(Collectors.toList());

            return listCvs;
        }
        return null;
    }

    @Override
    public void changeActionCv(long idNew, long idCv, String status, String content) {
        Optional<News> findNew = newsRepository.findById(idNew);
        List<DataSave> lisDataSave =  Arrays.stream(findNew.get().getListCV().split(";")).filter(s->!s.isBlank()).map(t->{
            Gson gson = new Gson();
            DataSave dataSave = gson.fromJson(t,DataSave.class);
            return dataSave;
        }).collect(Collectors.toList());

        DataSave dataUpdate = new DataSave();
        dataUpdate.setId(idCv);
        dataUpdate.setStatus(status);
        dataUpdate.setContent(content);

        for (int i = 0; i < lisDataSave.size(); i++) {
            if (lisDataSave.get(i).getId() == idCv){
                lisDataSave.set(i,dataUpdate);
            }
        }

        News news = findNew.get();
        news.setListCV(listCvUpdate(lisDataSave));
        newsRepository.save(news);
    }

    public String listCvUpdate(List<DataSave> dataSaves){
        String temp = ";";
        Gson gson = new Gson();
        for (int i = 0; i < dataSaves.size(); i++) {
            temp+=gson.toJson(dataSaves.get(i))+";";
        }
        return temp;
    }

    public static boolean isNumeric(String strNum) {
        if (strNum == null) {
            return false;
        }
        try {
            double d = Double.parseDouble(strNum);
        } catch (NumberFormatException nfe) {
            return false;
        }
        return true;
    }

    @Override
    public String addCv(long userId, CvRequest cvRequest) {
        Optional<Location> location = locationRepository.findById(cvRequest.getLocationId());
        Optional<Career> career = careerRepository.findById(cvRequest.getCareerId());
        String fileName = fileStorageService.getFileFromBase64(cvRequest);

            Cv cv = new Cv();
            cv.setCreateTime(new Date());
            cv.setNameFile(fileName);
            cv.setPathFile("active");
            cv.setSecurity("private");
            cv.setCareerCv(career.get());
            cv.setLocationCv(location.get());
            cvRepository.save(cv);
            Optional<Cv> cvFind = cvRepository.findByNameFile(fileName);
            Optional<User> findUser = userRepository.findById(userId);



            if (findUser.get() != null && cvFind.get() != null) {
                String listCvs = "";
                if (findUser.get().getCvs() == null) {
                    listCvs += cvFind.get().getIdCv() + ",";
                } else {
                    listCvs += findUser.get().getCvs() + cvFind.get().getIdCv() + ",";
                }
                User updateUser = findUser.get();
                updateUser.setCvs(listCvs);
                userRepository.save(updateUser);
                return "SUCCESS";
            }


        return "FAILED";
    }

    @Override
    public void changeSecurity(long idCv, String security) {
        Optional<Cv> findCvs = cvRepository.findById(idCv);
        if (findCvs.get() != null){
            Cv cvUpdate = findCvs.get();
            cvUpdate.setSecurity(security);
            cvRepository.save(cvUpdate);
        }
    }

    @Override
    public List<CvResponse> findCvs(String nameCv, Long careerId, Long locationId) {
        List<Cv> findCvs = cvRepository.findAll(new Specification<Cv>() {
            @Override
            public Predicate toPredicate(Root<Cv> root, CriteriaQuery<?> query, CriteriaBuilder criteriaBuilder) {
                Predicate p = criteriaBuilder.conjunction();
                if (!nameCv.isBlank()){
                    Predicate pKeyWork = criteriaBuilder.like(root.get("nameFile"),"%"+nameCv+"%");
                    p = criteriaBuilder.and(p,pKeyWork);
                }

                if (locationId != null && locationId != 0){
                    Predicate pLocation = criteriaBuilder.equal(root.join("locationCv").get("idLocation"),locationId);
                    p = criteriaBuilder.and(p,pLocation);
                }

                if (careerId != null && careerId != 0){
                    Predicate pCareer = criteriaBuilder.equal(root.join("careerCv").get("careerId"),careerId);
                    p = criteriaBuilder.and(p,pCareer);
                }
                return p;
            }
        });

        return findCvs.stream().filter(t->t.getSecurity().compareToIgnoreCase("public") == 0).map(t -> {
            CvResponse cvResponse = cvMapper.from(t);
            cvResponse.setCareerName(t.getCareerCv().getNameCareer());
            cvResponse.setLocationName(t.getLocationCv().getNameLocation());
            return cvResponse;
        }).collect(Collectors.toList());

    }

    @Override
    public List<CvResponse> findCvsPublic() {
        return  cvRepository.findAll().stream().filter(s->s.getSecurity().compareToIgnoreCase("public") == 0).map(t -> {
            CvResponse cvResponse = cvMapper.from(t);
            cvResponse.setCareerName(t.getCareerCv().getNameCareer());
            cvResponse.setLocationName(t.getLocationCv().getNameLocation());
            return cvResponse;
        }).collect(Collectors.toList());
    }

    @Override
    public List<NewHasCvResponse> myListCv(Long idUser) {
        Optional<User> findUser = userRepository.findById(idUser);
        List<NewHasCvResponse> listHas = new ArrayList<>();

        Arrays.stream(findUser.get().getApplyNews().split(";")).filter(s->!s.isBlank()).forEach(t->{

            String[] arrId = t.split("-");
            Optional<News> findNew = newsRepository.findById(Long.parseLong(arrId[0]));

            Arrays.stream(findNew.get().getListCV().split(";")).filter(d->!d.isBlank()).forEach(x->{
                Gson gson = new Gson();
                DataSave dataSave = gson.fromJson(x,DataSave.class);
                if (dataSave.getId() == Long.parseLong(arrId[1])){
                    NewHasCvResponse response = new NewHasCvResponse();
                    response.setNameNews(findNew.get().getTitleNew());
                    Optional<Cv> findCv = cvRepository.findById(Long.parseLong(arrId[1]));
                    response.setNameCv(findCv.get().getNameFile());
                    response.setStatus(dataSave.getStatus());
                    response.setContent(dataSave.getContent());
                    listHas.add(response);
                }
            });
        });

        return listHas;
    }

    @Override
    public void deleteCv(Long idUser, Long idCv) {
        Optional<User> findUser = userRepository.findById(idUser);
        User userUpdate = findUser.get();
        userUpdate.setCvs(findUser.get().getCvs().replace(","+idCv,""));
        userRepository.save(userUpdate);
    }


}
