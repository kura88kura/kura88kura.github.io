---
title:  "Rails API Setup"
date:   2016-02-01 10:18:00
description: Rails API
---

# Rails Api

## 搭建环境

{% highlight ruby %}
mkdir railsapisample
cd railsapisample
vim .rvmrc
{% endhighlight %}
> .rvmrc

{% highlight ruby %}
rvm use 2.1.5@rails420
{% endhighlight %}

{% highlight ruby %}
rails new railsapisample -d mysql
cd railsapisample
mysql.service start
{% endhighlight %}

> config/database.yml

{% highlight ruby %}
default: &default
  adapter: mysql2
  encoding: utf8
  pool: 5
  username: root
  password: # Your password
  socket: /tmp/mysql.sock
{% endhighlight %}

{% highlight ruby %}
rake db:create
rails s
{% endhighlight %}


> app/controllers/application_controller.rb
>

{% highlight ruby %}
class ApplicationController < ActionController::Base
  # Prevent CSRF attacks by raising an exception.
  # For APIs, you may want to use :null_session instead.
  protect_from_forgery with: :null_session

  # disable the CSRF token
  skip_before_action :verify_authenticity_token


  def page_not_found
    e = Error.new(:status => 404, :message => "Wrong URL or HTTP method")
    render :json => e.to_json, :status => 404
  end

end
{% endhighlight %}

{% highlight ruby %}
rails g controller api
rails g controller home
rails g model User
{% endhighlight %}

> db/migrate/20160128022807_create_users.rb

{% highlight ruby %}
class CreateUsers < ActiveRecord::Migration
  def change
    create_table :users do |t|
      t.string :first_name
      t.string :last_name
      t.string :email

      t.string :password_hash
      t.string :password_salt

      t.boolean :email_verification, :default => false
      t.string :verification_code

      t.string :api_authtoken
      t.datetime :authtoken_expiry

      t.timestamps
    end
  end
end
{% endhighlight %}

{% highlight ruby %}
rake db:migrate
{% endhighlight %}

> config/routes.rb

{% highlight ruby %}
Rails.application.routes.draw do
  root 'home#index'

  get 'home/index'

  post 'api/signup'
  post 'api/signin'
  post 'api/reset_password'

  post 'api/upload_photo'
  get 'api/get_photos'
  delete 'api/delete_photo'

  get 'api/get_token'
  get 'api/clear_token'

  match "*path", to: "application#page_not_found", via: :all
end
{% endhighlight %}

> app/models/user.rb

{% highlight ruby %}
class User < ActiveRecord::Base
  attr_accessor :password
  before_save :encrypt_password

  validates_confirmation_of :password
  validates_presence_of :email, :on => :create
  validates :password, length: { in: 6..30 }, :on => :create

  validates_format_of :email, :with => /\A[^@]+@([^@\.]+\.)+[^@\.]+\z/
  validates_uniqueness_of :email
  has_many :photos

  def encrypt_password
    if password.present?
      self.password_salt = BCrypt::Engine.generate_salt
      self.password_hash = BCrypt::Engine.hash_secret(password, password_salt)
    end
  end

  def self.authenticate(login_name, password)
    user = self.where("email =?", login_name).first

    if user
      puts "******************* #{password} 1"

      # begin
      #   password = AESCrypt.decrypt(password, "password")
      # rescue Exception => e
      #   password = nil
      #   puts "error - #{e.message}"
      # end

      puts "******************* #{password} 2"

      if user.password_hash == BCrypt::Engine.hash_secret(password, user.password_salt)
        user
      else
        nil
      end
    else
      nil
    end
  end

  def to_json(options={})
    options[:except] ||= [:id, :password_hash, :password_salt, :email_verification, :verification_code, :created_at, :updated_at]
    super(options)
  end
end
{% endhighlight %}

> app/controllers/api_controller.rb

{% highlight ruby %}
class ApiController < ApplicationController

  http_basic_authenticate_with name:"eason", password:"password", :only => [:signup, :signin, :get_token]
  before_filter :check_for_valid_authtoken, :except => [:signup, :signin, :get_token]

  def signup
    if request.post?
      if params && params[:full_name] && params[:email] && params[:password]

        params[:user] = Hash.new
        params[:user][:first_name] = params[:full_name].split(" ").first
        params[:user][:last_name] = params[:full_name].split(" ").last
        params[:user][:email] = params[:email]

        # begin
        #   decrypted_pass = AESCrypt.decrypt(params[:password], "password")
        # rescue Exception => e
        #   decrypted_pass = nil
        # end

        # params[:user][:password] = decrypted_pass
        params[:user][:password] = params[:password]
        params[:user][:verification_code] = rand_string(20)

        user = User.new(user_params)

        if user.save
          render :json => user.to_json, :status => 200
        else
          error_str = ""

          user.errors.each{|attr, msg|
            error_str += "#{attr} - #{msg},"
          }

          e = Error.new(:status => 400, :message => error_str)
          logger.info e.to_json
          render :json => e.to_json, :status => 400
        end
      else
        e = Error.new(:status => 400, :message => "required parameters are missing")
        render :json => e.to_json, :status => 400
      end
    end
  end

  def signin
    if request.post?
      if params && params[:email] && params[:password]
        user = User.where(:email => params[:email]).first

        if user
          if User.authenticate(params[:email], params[:password])

            if !user.api_authtoken || (user.api_authtoken && user.authtoken_expiry < Time.now)
              auth_token = rand_string(20)
              auth_expiry = Time.now + (24*60*60)

              user.update_attributes(:api_authtoken => auth_token, :authtoken_expiry => auth_expiry)
            end

            render :json => user.to_json, :status => 200
          else
            e = Error.new(:status => 401, :message => "Wrong Password")
            render :json => e.to_json, :status => 401
          end
        else
          e = Error.new(:status => 400, :message => "No USER found by this email ID")
          render :json => e.to_json, :status => 400
        end
      else
        e = Error.new(:status => 400, :message => "required parameters are missing")
        render :json => e.to_json, :status => 400
      end
    end
  end

  def reset_password
    if request.post?
      if params && params[:old_password] && params[:new_password]
        if @user
          if @user.authtoken_expiry > Time.now
            authenticate_user = User.authenticate(@user.email, params[:old_password])

            if authenticate_user && !authenticate_user.nil?
              auth_token = rand_string(20)
              auth_expiry = Time.now + (24*60*60)

              begin
                new_password = AESCrypt.decrypt(params[:new_password], "password")
              rescue Exception => e
                new_password = nil
                puts "error - #{e.message}"
              end

              new_password_salt = BCrypt::Engine.generate_salt
              new_password_digest = BCrypt::Engine.hash_secret(new_password, new_password_salt)

              @user.update_attributes(:password => new_password, :api_authtoken => auth_token, :authtoken_expiry => auth_expiry, :password_salt => new_password_salt, :password_hash => new_password_digest)
              render :json => @user.to_json, :status => 200
            else
              e = Error.new(:status => 401, :message => "Wrong Password")
              render :json => e.to_json, :status => 401
            end
          else
            e = Error.new(:status => 401, :message => "Authtoken is invalid or has expired. Kindly refresh the token and try again!")
            render :json => e.to_json, :status => 401
          end
        else
          e = Error.new(:status => 400, :message => "No user record found for this email ID")
          render :json => e.to_json, :status => 400
        end
      else
        e = Error.new(:status => 400, :message => "required parameters are missing")
        render :json => e.to_json, :status => 400
      end
    end
  end

  def get_token
    if params && params[:email]
      user = User.where(:email => params[:email]).first

      if user
        if !user.api_authtoken || (user.api_authtoken && user.authtoken_expiry < Time.now)
          auth_token = rand_string(20)
          auth_expiry = Time.now + (24*60*60)

          user.update_attributes(:api_authtoken => auth_token, :authtoken_expiry => auth_expiry)
        end

        render :json => user.to_json(:only => [:api_authtoken, :authtoken_expiry])
      else
        e = Error.new(:status => 400, :message => "No user record found for this email ID")
        render :json => e.to_json, :status => 400
      end

    else
      e = Error.new(:status => 400, :message => "required parameters are missing")
      render :json => e.to_json, :status => 400
    end
  end

  def clear_token
    if @user.api_authtoken && @user.authtoken_expiry > Time.now
      @user.update_attributes(:api_authtoken => nil, :authtoken_expiry => nil)

      m = Message.new(:status => 200, :message => "Token cleared")
      render :json => m.to_json, :status => 200
    else
      e = Error.new(:status => 401, :message => "You don't have permission to do this task")
      render :json => e.to_json, :status => 401
    end
  end

  private

  def check_for_valid_authtoken
    authenticate_or_request_with_http_token do |token, options|
      @user = User.where(:api_authtoken => token).first
    end
  end

  def rand_string(len)
    o =  [('a'..'z'),('A'..'Z')].map{|i| i.to_a}.flatten
    string  =  (0..len).map{ o[rand(o.length)]  }.join

    return string
  end

  def user_params
    params.require(:user).permit(:first_name, :last_name, :email, :password, :password_hash, :password_salt, :verification_code,
    :email_verification, :api_authtoken, :authtoken_expiry)
  end

end
{% endhighlight %}

> app/controller/home_controller.rb

{% highlight ruby %}
class HomeController < ApplicationController
  def index
    render inline: "Welcome to my API!"
  end
end
{% endhighlight %}

> Gemfile

{% highlight ruby %}
gem 'bcrypt'
gem 'aescrypt'
gem 'figaro'
gem 'rack-cors'
{% endhighlight %}
> config/application.rb

{% highlight ruby %}
   config.middleware.insert_before 0, "Rack::Cors" do
     allow do
       origins '*'
       resource '*', :headers => :any, :methods => [:get, :post, :put, :patch, :delete, :options, :head]
     end
   end

{% endhighlight %}

{% highlight ruby %}
bundle install
rails s
{% endhighlight %}


