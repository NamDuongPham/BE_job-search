package com.example.movieba.service.Impl;

import com.example.movieba.entities.*;
import com.example.movieba.exception.BusinessCode;
import com.example.movieba.exception.BusinessException;
import com.example.movieba.mapper.NewsMapper;
import com.example.movieba.model.request.json.DataSave;
import com.example.movieba.model.request.news.NewsRequest;
import com.example.movieba.model.response.news.NewsResponse;
import com.example.movieba.repository.*;
import com.example.movieba.repository.Specification.NewSpecification;
import com.example.movieba.security.JwtService;
import com.example.movieba.service.NewsService;
import com.example.movieba.utils.JwtUtils;
import com.google.gson.Gson;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import jakarta.servlet.http.HttpServletRequest;
import lombok.AllArgsConstructor;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;

@Service
@AllArgsConstructor
public class NewsServiceImpl implements NewsService {

    private final UserRepository userRepository;
    private final NewsMapper newsMapper;
    private final NewsRepository newsRepository;
    private final JwtService jwtService;

    private final CompanyRepository companyRepository;

    private final CvRepository cvRepository;

    private final LocationRepository locationRepository;

    private final CareerRepository careerRepository;

    @Override
    public void addNew(long idCom, NewsRequest newsRequest) {
        Optional<Company> findComs = companyRepository.findById(idCom);
        findComs.orElseThrow(()-> new BusinessException(BusinessCode.USER_NOT_FOUND));


        Date date = new Date();

        News news = newsMapper.to(newsRequest);
        news.setStatusNew("wait");
        news.setTimeNews(date);
        news.setLocalName(newsRequest.getLocalName());
        news.setSkill(newsRequest.getSkill());
        news.setWage(newsRequest.getWage());
        news.setListCV(";");

        Optional<Location> location  = locationRepository.findById(newsRequest.getIdLocation());
        Optional<Career> careers = careerRepository.findById(newsRequest.getIdCareer());
        news.setLocation(location.get());
        news.setCareer(careers.get());

        newsRepository.save(news);

        Optional<News> findNews = newsRepository.findByTimeNews(date);

        String listAs = "";
        if (findComs.get().getListNews() != null){
            listAs = findComs.get().getListNews() + findNews.get().getIdNew() + ",";
        }else {
            listAs += findNews.get().getIdNew() + ",";
        }


        Company company = findComs.get();
        company.setListNews(listAs);

        companyRepository.save(company);

    }

    @Override
    public void updateNew(long idNew, NewsRequest newsRequest) {
        Optional<News> findNews = newsRepository.findById(idNew);
        findNews.orElseThrow(()-> new BusinessException(BusinessCode.USER_NOT_FOUND));
//        Optional<Location> location  = locationRepository.findById(newsRequest.getIdLocation());
//        Optional<Career> careers = careerRepository.findById(newsRequest.getIdCareer());
        if (!findNews.isEmpty() ){
            News news = findNews.get();
            news.setDescribeNew(newsRequest.getDescribeNew());
            news.setTitleNew(news.getTitleNew());
//            news.setCareer(careers.get());
//            news.setLocation(location.get());
            news.setLocalName(newsRequest.getLocalName());
            news.setSkill(newsRequest.getSkill());
            news.setWage(newsRequest.getWage());
            newsRepository.save(news);
        }
    }

    @Override
    public void acceptNew(long idNew, String status) {
        Optional<News> findNews = newsRepository.findById(idNew);
        findNews.orElseThrow(()-> new BusinessException(BusinessCode.USER_NOT_FOUND));

        if (!findNews.isEmpty()){
            News news = findNews.get();
            news.setStatusNew(status);
            newsRepository.save(news);
        }
    }

    @Override
    public NewsResponse getNews(long idNew) {
        Optional<News> findNews = newsRepository.findById(idNew);
        findNews.orElseThrow(()-> new BusinessException(BusinessCode.USER_NOT_FOUND));
        long countCv = Arrays.stream(findNews.get().getListCV().split(",")).filter(t->isNumeric(t)).count();
        NewsResponse newsResponse = newsMapper.from(findNews.get());
        newsResponse.setCountCv(countCv);
        newsResponse.setNameCareer(findNews.get().getCareer().getNameCareer());
        newsResponse.setLocalName(findNews.get().getLocation().getNameLocation());
        return newsResponse;
    }

    @Override
    public List<NewsResponse> getAllNews() {
        List<News> listNews = newsRepository.findAll();
        return listNews.stream().map(t-> {
            NewsResponse newsResponse = newsMapper.from(t);
            long countCv = Arrays.stream(t.getListCV().split(",")).filter(s->isNumeric(s)).count();
            newsResponse.setCountCv(countCv);
            newsResponse.setNameCareer(t.getCareer().getNameCareer());
            newsResponse.setLocalName(t.getLocation().getNameLocation());
            return  newsResponse;
        }).filter(t->t.getStatusNew().compareToIgnoreCase("delete") != 0).sorted(Comparator.comparingLong(NewsResponse::getIdNew).reversed()).collect(Collectors.toList());
    }

    @Override
    public List<NewsResponse> filterNews() {
        List<News> listNews = newsRepository.findAll();
        return listNews.stream().map(t-> {
            NewsResponse newsResponse = newsMapper.from(t);
            long countCv = Arrays.stream(t.getListCV().split(",")).filter(s->isNumeric(s)).count();
            newsResponse.setCountCv(countCv);
            newsResponse.setNameCareer(t.getCareer().getNameCareer());
            newsResponse.setLocalName(t.getLocation().getNameLocation());
            return  newsResponse;
        }).sorted(Comparator.comparingLong(NewsResponse::getIdNew)
                .reversed()).filter(t->t.getStatusNew().compareToIgnoreCase("wait") != 0 && t.getStatusNew().compareToIgnoreCase("complete") != 0
                && t.getStatusNew().compareToIgnoreCase("delete") != 0)
                .collect(Collectors.toList());
    }

    @Override
    public int total() {
        return newsRepository.findAll().size();
    }

    @Override
    public List<NewsResponse> getAllNewsByIds(long idCom) {
        Optional<Company> findCompanies = companyRepository.findById(idCom);
        if (findCompanies.get()!= null){
            String []arrayId = findCompanies.get().getListNews().split(",");
            List<Long> longs = Arrays.stream(arrayId).map(t->Long.parseLong(t)).collect(Collectors.toList());

            return newsRepository.findAllByIdNewIsIn(longs).stream().map(t-> {
                NewsResponse newsResponse = newsMapper.from(t);
                long countCv = Arrays.stream(t.getListCV().split(";")).filter(s->!s.isBlank()).count();
                newsResponse.setCountCv(countCv);
                newsResponse.setNameCareer(t.getCareer().getNameCareer());
                newsResponse.setLocalName(t.getLocation().getNameLocation());
                return  newsResponse;
            }).filter(t->t.getStatusNew().compareToIgnoreCase("delete")!= 0).sorted(Comparator.comparingLong(NewsResponse::getIdNew).reversed()).collect(Collectors.toList());
        }
        return null;
    }

    @Override
    public Page<NewsResponse> getNewLimit(Pageable pageable) {
        Page<News> newsPage = newsRepository.findAll(pageable);
        return newsPage.map(t->{
            NewsResponse newsResponse = newsMapper.from(t);
            long countCv =Arrays.stream(t.getListCV().split(",")).filter(s->isNumeric(s)).count();
            newsResponse.setCountCv(countCv);
            newsResponse.setNameCareer(t.getCareer().getNameCareer());
            newsResponse.setLocalName(t.getLocation().getNameLocation());
            return newsResponse;
        });
    }

    @Override
    public int totalFindNews() {
        return (int) newsRepository.findAll().stream()
                .filter(t->t.getStatusNew().compareToIgnoreCase("wait") != 0 && t.getStatusNew().compareToIgnoreCase("complete") != 0)
                .count();
    }

    @Override
    public void applyJob(long idCv, long idNew, HttpServletRequest request) {
        Optional<News> findNews = newsRepository.findById(idNew);
        Optional<Cv> findCvs = cvRepository.findById(idCv);
        Gson gson = new Gson();
        DataSave dataSave = new DataSave();
        dataSave.setId(idCv);
        dataSave.setStatus("apply");
        dataSave.setContent("");

        String token = JwtUtils.getToken(request);

        String userName = jwtService.extractUsername(token);

        Optional<User> user = userRepository.findByUserName(userName);
        user.orElseThrow(() -> new BusinessException(BusinessCode.USER_NOT_FOUND));

        String listAp = "";
        User userUpdate = user.get();
        if (user.get().getApplyNews() == null){
            listAp+=";"+idNew + "-"+idCv+";";
        }else{
            listAp += user.get().getApplyNews() + idNew + "-"+idCv+";";
        }

        userUpdate.setApplyNews(listAp);
        userRepository.save(userUpdate);


        if (findNews.get()!= null && findCvs.get() != null){
            News upNews = findNews.get();
            String lists = "";
            if (findNews.get().getListCV()!=null){
                lists+= findNews.get().getListCV()+ gson.toJson(dataSave)+";";
            }else{
                lists+=gson.toJson(dataSave)+";";
            }
            upNews.setListCV(lists);
            newsRepository.save(upNews);
        }
    }

    @Override
    public NewsResponse getAllNewsByIdUser(long idUser) {
        Optional<User> findUser = userRepository.findById(idUser);
        if (findUser.get()!= null){
            Arrays.stream(findUser.get().getCvs().split(",")).filter(t->isNumeric(t)).map(d->{
                return newsRepository.findAll(NewSpecification.filterAll(Long.parseLong(d))).stream().map(s->{
                    return Arrays.stream(s.getListCV().split(",")).filter(c->c.compareTo(d) == 0).collect(Collectors.toList());
                }).collect(Collectors.toList());
            }).collect(Collectors.toList());

        }

        return null;
    }

    @Override
    public List<NewsResponse> findAllByKeyWord(String title, Long locationId, Long careerId,
                                               String skill, String des, String localName,
                                               String level, Integer sort) {

        List<News> news = newsRepository.findAll(new Specification<News>() {
            @Override
            public Predicate toPredicate(Root<News> root, CriteriaQuery<?> query, CriteriaBuilder criteriaBuilder) {
                Predicate p = criteriaBuilder.conjunction();
                if (!title.isBlank() && !skill.isBlank() && !des.isBlank() && !localName.isBlank()
                    && !level.isBlank()){
                    Predicate pKeyWork = criteriaBuilder.like(root.get("titleNew"),"%"+title+"%");
                    Predicate pSkill = criteriaBuilder.like(root.get("skill"),"%"+skill+"%");
                    Predicate pDes = criteriaBuilder.like(root.get("describeNew"),"%"+des+"%");
                    Predicate pLocalName = criteriaBuilder.like(root.get("localName"),"%"+localName+"%");
                    Predicate pLevel = criteriaBuilder.like(root.get("level"),"%"+level+"%");
                    Predicate predicate = criteriaBuilder.or(pKeyWork,pSkill,pDes,pLocalName,pLevel);
                    p = criteriaBuilder.and(p,predicate);
                }

                if (locationId != null && locationId != 0){
                    Predicate pLocation = criteriaBuilder.equal(root.join("location").get("idLocation"),locationId);
                    p = criteriaBuilder.and(p,pLocation);
                }

                if (careerId != null && careerId != 0){
                    Predicate pCareer = criteriaBuilder.equal(root.join("career").get("careerId"),careerId);
                    p = criteriaBuilder.and(p,pCareer);
                }

                if ( sort != null && sort == 0){
                    query.orderBy(criteriaBuilder.asc(root.get("idNew")));
                }

                if ( sort != null && sort == 1){
                    query.orderBy(criteriaBuilder.desc(root.get("idNew")));
                }

                return p;
            }
        });

        return news.stream().map(t-> {
                    NewsResponse newsResponse = newsMapper.from(t);
                    long countCv = Arrays.stream(t.getListCV().split(",")).filter(s->isNumeric(s)).count();
                    newsResponse.setCountCv(countCv);
                    newsResponse.setNameCareer(t.getCareer().getNameCareer());
                    newsResponse.setLocalName(t.getLocation().getNameLocation());
                    return  newsResponse;
                }).filter(t->t.getStatusNew().compareToIgnoreCase("wait") != 0 && t.getStatusNew().compareToIgnoreCase("complete") != 0)
                .collect(Collectors.toList());
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


//    public static boolean isIdCVIn(Long idCv) {
//        if (strNum == null) {
//            return false;
//        }
//        try {
//            double d = Double.parseDouble(strNum);
//        } catch (NumberFormatException nfe) {
//            return false;
//        }
//        return true;
//    }




}
