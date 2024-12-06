FROM node:alpine
#FROM node:18.0.4 as build

# Set the working directory to /app
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . .

# Install angular
RUN npm install -g @angular/cli
RUN npm install
RUN npm install ngx-echarts echarts --save

#RUN npm run build

#COPY . .

#RUN ng build
#RUN ng build --configuration=production

# Make port 4200 available to the world outside this container
EXPOSE 4200

CMD ["ng", "serve", "--host", "0.0.0.0"]
