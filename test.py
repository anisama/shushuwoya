  page = 1
    image_names = list(ImageInfo.objects.all().values_list('image_name', flat=True))
    req = None
    while True:
        url = "https://vulfocus.cn/api/imgs/info"
        try:
            res = requests.get(url, verify=False, params={"page": page}).content
            req = json.loads(res)
        except Exception as e:
            return
        if "total_page" in req and page > req["total_page"]:
            return
        for item in req["imgs"]:
            if item['image_name'] == "":
                continue
            if 'is_docker_compose' in item:
                if item['is_docker_compose'] == True:
                    continue
            if item['image_name'] in image_names:
                if item['image_name'] == "vulfocus/vulfocus:latest":
                    continue
                single_img = ImageInfo.objects.filter(image_name__contains=item['image_name']).first()
                if single_img.image_vul_name != item['image_vul_name'] or single_img.image_vul_name == "":
                    single_img.image_vul_name = item['image_vul_name']
                if single_img.image_desc == "":
                    single_img.image_desc = item['image_desc']
                if single_img.rank != item['rank']:
                    single_img.rank = item['rank']
                if single_img.degree != item['degree']:
                    single_img.degree = json.dumps(item['degree'])
                if "writeup_date" in item and single_img.writeup_date != item['writeup_date']:
                    single_img.writeup_date = item['writeup_date']
                single_img.save()
            else:
                if "writeup_date" in item:
                    writeup_date = item['writeup_date']
                else:
                    writeup_date = ""
                image_info = ImageInfo(image_name=item['image_name'], image_vul_name=item['image_vul_name'],
                                       image_desc=item['image_desc'], rank=item['rank'],
                                       degree=json.dumps(item['degree']), writeup_date=writeup_date,
                                       is_ok=False, create_date=timezone.now(), update_date=timezone.now())
                image_info.save()
        page += 1
        return JsonResponse({"code": 200, "data": "成功"})