package logparser;

import logparser.query.*;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class LogParser implements IPQuery, UserQuery, DateQuery, EventQuery, QLQuery {
    private Path logDir;
    private List<LogEntity> logEntities = new ArrayList<>();
    private DateFormat simpleDateFormat = new SimpleDateFormat("d.M.yyyy H:m:s");

    public LogParser(Path logDir) {
        this.logDir = logDir;
        readLogs();
    }

    @Override
    public int getNumberOfUniqueIPs(Date after, Date before) {
        return getUniqueIPs(after, before).size();
    }

    @Override
    public Set<String> getUniqueIPs(Date after, Date before) {
        Set<String> result = new HashSet<>();
        for (int i = 0; i < logEntities.size(); i++) {
            if (dateBetweenDates(logEntities.get(i).getDate(), after, before)) {
                result.add(logEntities.get(i).getIp());
            }
        }
        return result;
    }

    @Override
    public Set<String> getIPsForUser(String user, Date after, Date before) {
        Set<String> result = new HashSet<>();
        for (int i = 0; i < logEntities.size(); i++) {
            if (dateBetweenDates(logEntities.get(i).getDate(), after, before)) {
                if (logEntities.get(i).getUser().equals(user)) {
                    result.add(logEntities.get(i).getIp());
                }
            }
        }
        return result;
    }

    @Override
    public Set<String> getIPsForEvent(Event event, Date after, Date before) {
        Set<String> result = new HashSet<>();
        for (int i = 0; i < logEntities.size(); i++) {
            if (dateBetweenDates(logEntities.get(i).getDate(), after, before)) {
                if (logEntities.get(i).getEvent().equals(event)) {
                    result.add(logEntities.get(i).getIp());
                }
            }
        }
        return result;
    }

    @Override
    public Set<String> getIPsForStatus(Status status, Date after, Date before) {
        Set<String> result = new HashSet<>();
        for (int i = 0; i < logEntities.size(); i++) {
            if (dateBetweenDates(logEntities.get(i).getDate(), after, before)) {
                if (logEntities.get(i).getStatus().equals(status)) {
                    result.add(logEntities.get(i).getIp());
                }
            }
        }
        return result;
    }

    private void readLogs() {
        try (DirectoryStream<Path> directoryStream = Files.newDirectoryStream(logDir)) {
            for (Path file : directoryStream) {
                if (file.toString().toLowerCase().endsWith(".log")) {
                    try (BufferedReader reader = new BufferedReader(new FileReader(file.toFile()))) {
                        String line = null;
                        while ((line = reader.readLine()) != null) {
                            String[] params = line.split("\t");

                            if (params.length != 5) {
                                continue;
                            }

                            String ip = params[0];
                            String user = params[1];
                            Date date = readDate(params[2]);
                            Event event = readEvent(params[3]);
                            int eventAdditionalParameter = -1;
                            if (event.equals(Event.SOLVE_TASK) || event.equals(Event.DONE_TASK)) {
                                eventAdditionalParameter = readAdditionalParameter(params[3]);
                            }
                            Status status = readStatus(params[4]);

                            LogEntity logEntity = new LogEntity(ip, user, date, event, eventAdditionalParameter, status);
                            logEntities.add(logEntity);
                        }
                    }
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private Date readDate(String lineToParse) {
        Date date = null;
        try {
            date = simpleDateFormat.parse(lineToParse);
        } catch (ParseException e) {
        }
        return date;
    }

    private Event readEvent(String lineToParse) {
        Event event = null;
        if (lineToParse.contains("SOLVE_TASK")) {
            event = Event.SOLVE_TASK;
        } else if (lineToParse.contains("DONE_TASK")) {
            event = Event.DONE_TASK;
        } else {
            switch (lineToParse) {
                case "LOGIN": {
                    event = Event.LOGIN;
                    break;
                }
                case "DOWNLOAD_PLUGIN": {
                    event = Event.DOWNLOAD_PLUGIN;
                    break;
                }
                case "WRITE_MESSAGE": {
                    event = Event.WRITE_MESSAGE;
                    break;
                }
            }
        }
        return event;
    }

    private int readAdditionalParameter(String lineToParse) {
        if (lineToParse.contains("SOLVE_TASK")) {
            lineToParse = lineToParse.replace("SOLVE_TASK", "").replaceAll(" ", "");
            return Integer.parseInt(lineToParse);
        } else {
            lineToParse = lineToParse.replace("DONE_TASK", "").replaceAll(" ", "");
            return Integer.parseInt(lineToParse);
        }
    }

    private Status readStatus(String lineToParse) {
        Status status = null;
        switch (lineToParse) {
            case "OK": {
                status = Status.OK;
                break;
            }
            case "FAILED": {
                status = Status.FAILED;
                break;
            }
            case "ERROR": {
                status = Status.ERROR;
                break;
            }
        }
        return status;
    }

    private boolean dateBetweenDates(Date current, Date after, Date before) {
        if (after == null) {
            after = new Date(0);
        }
        if (before == null) {
            before = new Date(Long.MAX_VALUE);
        }
        return current.after(after) && current.before(before);
    }

    @Override
    public Set<String> getAllUsers() {
        Set<String> allUsers = new HashSet<>();
        for (LogEntity le : logEntities) {
            allUsers.add(le.getUser());
        }
        return allUsers;
    }

    @Override
    public int getNumberOfUsers(Date after, Date before) {
        Set<String> uniqueUsers = new HashSet<>();
        for (LogEntity le : logEntities) {
            if (dateBetweenDates(le.getDate(), after, before))
                uniqueUsers.add(le.getUser());
        }
        return uniqueUsers.size();
    }

    @Override
    public int getNumberOfUserEvents(String user, Date after, Date before) {
        Set<Event> uniqueEvents = new HashSet<>();
        for (LogEntity le : logEntities) {
            if (user.equals(le.getUser()) && dateBetweenDates(le.getDate(), after, before))
                uniqueEvents.add(le.getEvent());
        }
        return uniqueEvents.size();
    }

    @Override
    public Set<String> getUsersForIP(String ip, Date after, Date before) {
        Set<String> users = new HashSet<>();
        for (LogEntity le : logEntities) {
            if (ip.equals(le.getIp()) && dateBetweenDates(le.getDate(), after, before))
                users.add(le.getUser());
        }
        return users;
    }

    @Override
    public Set<String> getLoggedUsers(Date after, Date before) {
        Set<String> users = new HashSet<>();
        for (LogEntity le : logEntities) {
            if (le.getEvent() == Event.LOGIN && dateBetweenDates(le.getDate(), after, before))
                users.add(le.getUser());
        }
        return users;
    }

    @Override
    public Set<String> getDownloadedPluginUsers(Date after, Date before) {
        Set<String> users = new HashSet<>();
        for (LogEntity le : logEntities) {
            if (le.getEvent() == Event.DOWNLOAD_PLUGIN && dateBetweenDates(le.getDate(), after, before))
                users.add(le.getUser());
        }
        return users;
    }

    @Override
    public Set<String> getWroteMessageUsers(Date after, Date before) {
        Set<String> users = new HashSet<>();
        for (LogEntity le : logEntities) {
            if (le.getEvent() == Event.WRITE_MESSAGE && dateBetweenDates(le.getDate(), after, before))
                users.add(le.getUser());
        }
        return users;
    }

    @Override
    public Set<String> getSolvedTaskUsers(Date after, Date before) {
        Set<String> users = new HashSet<>();
        for (LogEntity le : logEntities) {
            if (le.getEvent() == Event.SOLVE_TASK && dateBetweenDates(le.getDate(), after, before))
                users.add(le.getUser());
        }
        return users;
    }

    @Override
    public Set<String> getSolvedTaskUsers(Date after, Date before, int task) {
        Set<String> users = new HashSet<>();
        for (LogEntity le : logEntities) {
            if (le.getEvent() == Event.SOLVE_TASK && le.getEventAdditionalParameter() == task &&
                    dateBetweenDates(le.getDate(), after, before))

                users.add(le.getUser());
        }
        return users;
    }

    @Override
    public Set<String> getDoneTaskUsers(Date after, Date before) {
        Set<String> users = new HashSet<>();
        for (LogEntity le : logEntities) {
            if (le.getEvent() == Event.DONE_TASK && dateBetweenDates(le.getDate(), after, before))
                users.add(le.getUser());
        }
        return users;
    }

    @Override
    public Set<String> getDoneTaskUsers(Date after, Date before, int task) {
        Set<String> users = new HashSet<>();
        for (LogEntity le : logEntities) {
            if (le.getEvent() == Event.DONE_TASK && le.getEventAdditionalParameter() == task &&
                    dateBetweenDates(le.getDate(), after, before))

                users.add(le.getUser());
        }
        return users;
    }

    @Override
    public Set<Date> getDatesForUserAndEvent(String user, Event event, Date after, Date before) {
        Set<Date> dates = new HashSet<>();
        for (LogEntity le : logEntities) {
            if (le.getUser().equals(user) && le.getEvent() == event &&
                    dateBetweenDates(le.getDate(), after, before)) {

                dates.add(le.getDate());
            }
        }
        return dates;
    }

    @Override
    public Set<Date> getDatesWhenSomethingFailed(Date after, Date before) {
        Set<Date> dates = new HashSet<>();
        for (LogEntity le : logEntities) {
            if (le.getStatus() == Status.FAILED &&
                    dateBetweenDates(le.getDate(), after, before)) {

                dates.add(le.getDate());
            }
        }
        return dates;
    }

    @Override
    public Set<Date> getDatesWhenErrorHappened(Date after, Date before) {
        Set<Date> dates = new HashSet<>();
        for (LogEntity le : logEntities) {
            if (le.getStatus() == Status.ERROR &&
                    dateBetweenDates(le.getDate(), after, before)) {

                dates.add(le.getDate());
            }
        }
        return dates;
    }

    @Override
    public Date getDateWhenUserLoggedFirstTime(String user, Date after, Date before) {
        Date loggedFirstTime = new Date(Long.MAX_VALUE);
        for (LogEntity le : logEntities) {
            if (le.getUser().equals(user) && le.getEvent() == Event.LOGIN &&
                    dateBetweenDates(le.getDate(), after, before) &&
                    le.getDate().getTime() < loggedFirstTime.getTime()) {

                loggedFirstTime = le.getDate();
            }
        }
        return loggedFirstTime.getTime() == Long.MAX_VALUE ? null : loggedFirstTime;
    }

    @Override
    public Date getDateWhenUserSolvedTask(String user, int task, Date after, Date before) {
        Date solvedFirstTime = new Date(Long.MAX_VALUE);
        for (LogEntity le : logEntities) {
            if (le.getUser().equals(user) && le.getEvent() == Event.SOLVE_TASK &&
                    le.getEventAdditionalParameter() == task &&
                    dateBetweenDates(le.getDate(), after, before) &&
                    le.getDate().getTime() < solvedFirstTime.getTime()) {

                solvedFirstTime = le.getDate();
            }
        }
        return solvedFirstTime.getTime() == Long.MAX_VALUE ? null : solvedFirstTime;
    }

    @Override
    public Date getDateWhenUserDoneTask(String user, int task, Date after, Date before) {
        Date doneFirstTime = new Date(Long.MAX_VALUE);
        for (LogEntity le : logEntities) {
            if (le.getUser().equals(user) && le.getEvent() == Event.DONE_TASK &&
                    le.getEventAdditionalParameter() == task &&
                    dateBetweenDates(le.getDate(), after, before) &&
                    le.getDate().getTime() < doneFirstTime.getTime()) {

                doneFirstTime = le.getDate();
            }
        }
        return doneFirstTime.getTime() == Long.MAX_VALUE ? null : doneFirstTime;
    }

    @Override
    public Set<Date> getDatesWhenUserWroteMessage(String user, Date after, Date before) {
        Set<Date> dates = new HashSet<>();
        for (LogEntity le : logEntities) {
            if (le.getUser().equals(user) && le.getEvent() == Event.WRITE_MESSAGE &&
                    dateBetweenDates(le.getDate(), after, before)) {

                dates.add(le.getDate());
            }
        }
        return dates;
    }

    @Override
    public Set<Date> getDatesWhenUserDownloadedPlugin(String user, Date after, Date before) {
        Set<Date> dates = new HashSet<>();
        for (LogEntity le : logEntities) {
            if (le.getUser().equals(user) && le.getEvent() == Event.DOWNLOAD_PLUGIN &&
                    dateBetweenDates(le.getDate(), after, before)) {

                dates.add(le.getDate());
            }
        }
        return dates;
    }

    @Override
    public int getNumberOfAllEvents(Date after, Date before) {
        return getAllEvents(after, before).size();
    }

    @Override
    public Set<Event> getAllEvents(Date after, Date before) {
        return logEntities.stream().
                filter(logEntity -> dateBetweenDates(logEntity.getDate(), after, before)).
                map(LogEntity::getEvent).
                collect(Collectors.toSet());
    }

    @Override
    public Set<Event> getEventsForIP(String ip, Date after, Date before) {
        return logEntities.stream().
                filter(logEntity -> logEntity.getIp().equals(ip)).
                filter(logEntity -> dateBetweenDates(logEntity.getDate(), after, before)).
                map(LogEntity::getEvent).
                collect(Collectors.toSet());
    }

    @Override
    public Set<Event> getEventsForUser(String user, Date after, Date before) {
        return logEntities.stream().
                filter(logEntity -> logEntity.getUser().equals(user)).
                filter(logEntity -> dateBetweenDates(logEntity.getDate(), after, before)).
                map(LogEntity::getEvent).
                collect(Collectors.toSet());
    }

    @Override
    public Set<Event> getFailedEvents(Date after, Date before) {
        return logEntities.stream().
                filter(logEntity -> logEntity.getStatus() == Status.FAILED).
                filter(logEntity -> dateBetweenDates(logEntity.getDate(), after, before)).
                map(LogEntity::getEvent).
                collect(Collectors.toSet());
    }

    @Override
    public Set<Event> getErrorEvents(Date after, Date before) {
        return logEntities.stream().
                filter(logEntity -> logEntity.getStatus() == Status.ERROR).
                filter(logEntity -> dateBetweenDates(logEntity.getDate(), after, before)).
                map(LogEntity::getEvent).
                collect(Collectors.toSet());
    }

    @Override
    public int getNumberOfAttemptToSolveTask(int task, Date after, Date before) {
        return (int) logEntities.stream().
                filter(logEntity -> logEntity.getEvent() == Event.SOLVE_TASK).
                filter(logEntity -> logEntity.getEventAdditionalParameter() == task).
                filter(logEntity -> dateBetweenDates(logEntity.getDate(), after, before)).
                count();
    }

    @Override
    public int getNumberOfSuccessfulAttemptToSolveTask(int task, Date after, Date before) {
        return (int) logEntities.stream().
                filter(logEntity -> logEntity.getEvent() == Event.DONE_TASK).
                filter(logEntity -> logEntity.getEventAdditionalParameter() == task).
                filter(logEntity -> dateBetweenDates(logEntity.getDate(), after, before)).
                count();
    }

    @Override
    public Map<Integer, Integer> getAllSolvedTasksAndTheirNumber(Date after, Date before) {
        return logEntities.stream().
                filter(logEntity -> logEntity.getEvent() == Event.SOLVE_TASK).
                filter(logEntity -> dateBetweenDates(logEntity.getDate(), after, before)).
                collect(Collectors.toMap(LogEntity::getEventAdditionalParameter,
                        logEntity -> getNumberOfAttemptToSolveTask(logEntity.getEventAdditionalParameter(), after, before),
                        (task, number) -> task));
    }

    @Override
    public Map<Integer, Integer> getAllDoneTasksAndTheirNumber(Date after, Date before) {
        return logEntities.stream().
                filter(logEntity -> logEntity.getEvent() == Event.DONE_TASK).
                filter(logEntity -> dateBetweenDates(logEntity.getDate(), after, before)).
                collect(Collectors.toMap(LogEntity::getEventAdditionalParameter,
                        logEntity -> getNumberOfSuccessfulAttemptToSolveTask(logEntity.getEventAdditionalParameter(), after, before),
                        (task, number) -> task));
    }

    @Override
    public Set<Object> execute(String query) {
        String get;
        String filter = null;
        String value = null;
        String after = null;
        String before = null;
        Pattern pattern = Pattern.compile("get (ip|user|date|event|status)"
                + "( for (ip|user|date|event|status) = \"(.*?)\")?" + "( and date between \"(.*?)\" and \"(.*?)\")?");
        Matcher matcher = pattern.matcher(query);
        matcher.find();
        get = matcher.group(1);
        if (matcher.group(2) != null) {
            filter = matcher.group(3);
            value = matcher.group(4);
        }

        if (matcher.group(5) != null) {
            after = matcher.group(6);
            before = matcher.group(7);
        }


        List<LogEntity> filteredLogEntities = logEntities;
        if (filter != null && value != null) {
            String finValue = value;
            switch (filter) {
                case "ip":
                    filteredLogEntities = logEntities.stream().
                            filter(logEntity -> logEntity.getIp().equals(finValue)).
                            collect(Collectors.toList());
                    break;
                case "user":
                    filteredLogEntities = logEntities.stream().
                            filter(logEntity -> logEntity.getUser().equals(finValue)).
                            collect(Collectors.toList());
                    break;
                case "date":
                    try {
                        Date vDate = simpleDateFormat.parse(finValue);
                        filteredLogEntities = logEntities.stream().
                                filter(logEntity -> logEntity.getDate().getTime() == vDate.getTime()).
                                collect(Collectors.toList());
                    } catch (ParseException e) {
                        e.printStackTrace();
                    }
                    break;
                case "event":
                    filteredLogEntities = logEntities.stream().
                            filter(logEntity -> logEntity.getEvent() == Event.valueOf(finValue)).
                            collect(Collectors.toList());
                    break;
                case "status":
                    filteredLogEntities = logEntities.stream().
                            filter(logEntity -> logEntity.getStatus() == Status.valueOf(finValue)).
                            collect(Collectors.toList());
                    break;
            }
        }

        if (after != null && before != null) {
            try {
                Date afterDate = simpleDateFormat.parse(after);
                Date beforeDate = simpleDateFormat.parse(before);
                filteredLogEntities = filteredLogEntities.stream().
                        filter(logEntity -> dateBetweenDates(logEntity.getDate(), afterDate, beforeDate)).
                        collect(Collectors.toList());

            } catch (ParseException e) {
                e.printStackTrace();
            }
        }

        switch (get) {
            case "ip":
                return filteredLogEntities.stream().map(LogEntity::getIp).collect(Collectors.toSet());
            case "user":
                return filteredLogEntities.stream().map(LogEntity::getUser).collect(Collectors.toSet());
            case "date":
                return filteredLogEntities.stream().map(LogEntity::getDate).collect(Collectors.toSet());
            case "event":
                return filteredLogEntities.stream().map(LogEntity::getEvent).collect(Collectors.toSet());
            case "status":
                return filteredLogEntities.stream().map(LogEntity::getStatus).collect(Collectors.toSet());
            default:
                return null;
        }
    }

    private class LogEntity {
        private String ip;
        private String user;
        private Date date;
        private Event event;
        private int eventAdditionalParameter;
        private Status status;

        public LogEntity(String ip, String user, Date date, Event event, int eventAdditionalParameter, Status status) {
            this.ip = ip;
            this.user = user;
            this.date = date;
            this.event = event;
            this.eventAdditionalParameter = eventAdditionalParameter;
            this.status = status;
        }

        public String getIp() {
            return ip;
        }

        public String getUser() {
            return user;
        }

        public Date getDate() {
            return date;
        }

        public Event getEvent() {
            return event;
        }

        public int getEventAdditionalParameter() {
            return eventAdditionalParameter;
        }

        public Status getStatus() {
            return status;
        }
    }
}