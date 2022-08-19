#!/usr/bin/env python3
from bs4 import BeautifulSoup
from jinja2 import Template, Environment
import markdown
from markdown.extensions.toc import TocExtension
import frontmatter
import shutil
import math
import os
import urllib.parse
import datetime

BASE_DOMAIN = "https://secoats.github.io"
BASE_DIR = os.getcwd()
DIST_DIRECTORY = BASE_DIR + "/dist"
ASSETS_DIRECTORY = BASE_DIR + "/assets"
TEMPLATE_DIRECTORY = BASE_DIR + "/templates"
POSTS_DIRECTORY = BASE_DIR + "/markdown"

template_default_head = Template(open(TEMPLATE_DIRECTORY + '/template_head.j2.html').read()).render()
template_navigation = Template(open(TEMPLATE_DIRECTORY + '/template_navigation.j2.html').read()).render()
template_footer = Template(open(TEMPLATE_DIRECTORY + '/template_footer.j2.html').read()).render()

def parse_yaml_meta(content):
    post = frontmatter.loads(content)
    return post.metadata, post.content

def parse_markdown(content):
    headline_anchor = " " # putting one with css :before later
    extension_configs = {
        'codehilite': {
            'css_class': 'highlight'
        }
    }

    html = markdown.markdown(content, extensions=['fenced_code', 'codehilite', TocExtension(baselevel=1, permalink=headline_anchor)], extension_configs=extension_configs)
    return html

def calc_reading_time(raw_text):
    word_count = len(raw_text.split())
    reading_time = math.ceil(word_count / 238) # average reading time is 238 words per minute
    return reading_time

def build_blogpost(raw_content, template, output_path):

    # split yaml frontmatter from markdown
    metadata, markdown_text = parse_yaml_meta(raw_content)

    # meta
    title = metadata.get("title")
    publish_date = metadata.get("published")
    publish_date_format = publish_date.strftime("%B %d, %Y")
    updated_date = metadata.get("updated")
    updated_date_format = updated_date.strftime("%B %d, %Y")
    reading_time = calc_reading_time(markdown_text)
    tags = metadata.get("tags")
    categories = metadata.get("categories")

    image = None
    if "image" in metadata:
        image = metadata.get("image")

    print("title", title)
    print("publish_date", publish_date, publish_date_format)
    print("updated_date", updated_date, updated_date_format)
    print("reading_time", reading_time)
    print("tags", tags)
    print("cats", categories)
    print("image", image)

    # turn markdown into html    
    markdown_html = parse_markdown(markdown_text)

    # postprocess the html to fit my layout (kinda ugly)
    # I was too lazy to write some extensions to the markdown lib
    markdown_html = post_process(markdown_html)

    permalink = BASE_DOMAIN + output_path
    twitter_share = "https://twitter.com/intent/tweet?text=" + urllib.parse.quote(title + " " + permalink, safe='')
    facebook_share = "https://www.facebook.com/sharer/sharer.php?u=" + urllib.parse.quote(permalink, safe='')
    linkedin_share = "https://www.linkedin.com/shareArticle?mini=true&url=" + urllib.parse.quote(permalink, safe='')

    print(twitter_share)
    print(facebook_share)
    print(linkedin_share)

    custom_metadata = {
        'reading_time': reading_time,
        'publish_date': publish_date_format,
        'permalink': permalink
    }

    templated_html = template.render(
        default_head=template_default_head,
        navigation=template_navigation,
        footer=template_footer,
        permalink=permalink,
        twitter_share=twitter_share,
        facebook_share=facebook_share,
        linkedin_share=linkedin_share,
        article_content=markdown_html, 
        article_title=title, 
        article_reading_time=reading_time, 
        article_published=publish_date_format,
        article_published_raw=publish_date,
        article_updated=updated_date_format,
        article_updated_raw=updated_date,
        article_tags=tags,
        article_categories=categories,
        article_image=image)

    #broth = post_process(templated_html)
    broth = templated_html
    
    #open(outputfile, 'w').write(broth)
    return broth, tags, categories, metadata, custom_metadata


def post_process(html_text):
    soup = BeautifulSoup(html_text, 'html.parser')
    
    # custom code blocks
    multiline_codeblocks = soup.findAll("div", {"class": "highlight"})
    for codeblock in multiline_codeblocks:
        div_breaker = soup.new_tag("div", attrs={"class": "breaker"})
        div_repairman = soup.new_tag("div", attrs={"class": "repairman"})
        codeblock.wrap(div_repairman)
        div_repairman.wrap(div_breaker)

    # custom image wrapper
    image_tags = soup.findAll("img")
    for image in image_tags:
        div_breaker = soup.new_tag("div", attrs={"class": "breaker breaker-image"})
        div_repairman = soup.new_tag("div", attrs={"class": "repairman"})
        image.wrap(div_repairman)
        div_repairman.wrap(div_breaker)

    #broth_cube = str(soup.prettify())
    broth_cube = str(soup)
    return broth_cube

def setup_dist():
    # recreate /dist
    shutil.rmtree(DIST_DIRECTORY)
    os.mkdir(DIST_DIRECTORY)
    os.mkdir(DIST_DIRECTORY + "/posts")

    nj = open(DIST_DIRECTORY + "/.nojekyll", "w")
    nj.write("")
    nj.close()

    # copy /assets
    src_path = ASSETS_DIRECTORY
    dst_path = DIST_DIRECTORY + "/assets"
    shutil.copytree(src_path, dst_path, symlinks=False, ignore=None, ignore_dangling_symlinks=False, dirs_exist_ok=True)


def post_sort_param(e):
  return e.get('metadata').get("published")

def convert_blogposts():
    template = Template(open(TEMPLATE_DIRECTORY + '/template_blogpost.j2.html').read())
    filenames = os.listdir(POSTS_DIRECTORY)

    posts = []

    for filename in filenames:
        
        output_name = filename.replace(".md", "") + ".html"
        output_path = "/posts/" + output_name

        raw_content = open(POSTS_DIRECTORY + "/" + filename, "r").read()
        blogpost, tags, cats, metadata, custom_metadata = build_blogpost(raw_content, template, output_path)

        posts.append( {
            'content': blogpost,
            'tags': tags,
            'cats': cats,
            'path': output_path,
            'metadata': metadata,
            'custom_metadata': custom_metadata
        })

        open(DIST_DIRECTORY + output_path, 'w').write(blogpost)

    posts.sort(key=post_sort_param, reverse=True)

    return posts


def convert_mainpage(posts):
    template = Template(open(TEMPLATE_DIRECTORY + '/template_mainpage.j2.html').read())
    mainpage = build_mainpage(template, posts)
    open(DIST_DIRECTORY + "/index.html", 'w').write(mainpage)

    
def build_mainpage(template, posts):
    print("Building main page")
    return template.render(default_head=template_default_head,navigation=template_navigation, footer=template_footer, posts=posts)


def convert_postspage(posts):
    template = Template(open(TEMPLATE_DIRECTORY + '/template_posts.j2.html').read())
    postspage = build_postspage(template, posts)
    open(DIST_DIRECTORY + "/posts.html", 'w').write(postspage)

def build_postspage(template, posts):
    print("Building posts page")
    return template.render(default_head=template_default_head,navigation=template_navigation, footer=template_footer, posts=posts)


def convert_catpage(posts):
    template = Template(open(TEMPLATE_DIRECTORY + '/template_categories.j2.html').read())
    catpage = build_catpage(template, posts)
    open(DIST_DIRECTORY + "/categories.html", 'w').write(catpage)


def build_catpage(template, posts):
    print("Building categories page")

    posts_by_categories = {}

    for post in posts:
        local_cats = post.get('cats')
        for cat in local_cats:
            if not cat in posts_by_categories:
                posts_by_categories[cat] = []
            
            #posts_by_categories[cat].append(post.get("metadata").get("title"))
            posts_by_categories[cat].append(post)
            
    #print(posts_by_categories)

    return template.render(default_head=template_default_head, navigation=template_navigation, footer=template_footer, posts=posts, categories=posts_by_categories)


def convert_tagpage(posts):
    template = Template(open(TEMPLATE_DIRECTORY + '/template_tags.j2.html').read())
    catpage = build_tagpage(template, posts)
    open(DIST_DIRECTORY + "/tags.html", 'w').write(catpage)


def build_tagpage(template, posts):
    print("Building tags page")

    posts_by_tags = {}

    for post in posts:
        local_tags = post.get('tags')
        for tag in local_tags:
            if not tag in posts_by_tags:
                posts_by_tags[tag] = []
            
            #posts_by_categories[cat].append(post.get("metadata").get("title"))
            posts_by_tags[tag].append(post)
            
    return template.render(default_head=template_default_head, navigation=template_navigation, footer=template_footer, posts=posts, tags=posts_by_tags, sorted=sorted)

def make_sitemap(posts):
    print("Building sitemap")
    template = Template(open(TEMPLATE_DIRECTORY + '/sitemap.j2.xml').read())
    sitemap = template.render(posts=posts, default_date=datetime.datetime.now().astimezone().replace(microsecond=0).isoformat())

    open(DIST_DIRECTORY + "/sitemap.xml", 'w').write(sitemap)
    open(DIST_DIRECTORY + "/sitemap_google.xml", 'w').write(sitemap)


setup_dist()

posts = convert_blogposts()

convert_mainpage(posts)
convert_postspage(posts)
convert_catpage(posts)
convert_tagpage(posts)
make_sitemap(posts)
print(".........")