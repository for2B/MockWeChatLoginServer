package TBCache


import (
	"sync"
	"fmt"
	"container/list"
	"time"
	."MockWeChatLogin/src/TBLogger"
)


type TBCache struct {
	RwLock *sync.RWMutex    //读写互斥锁
	MaxEntries int			//最大缓存数
	Bucket *CacheContainer 	//缓存容器
	ObjectPool *sync.Pool 	//对象池
	DfExpiration int64 		//默认过期时间 ,单位秒
	periodTime int 			//周期时间，定时清理过期缓存,单位秒
	Ticker *time.Ticker		//计时器
}

//缓存容器
type CacheContainer struct {
	BucketMap map[interface{}]*list.Element  //key-value,value为指向链表中某一项的指针
	CacheList *list.List				//缓存所在的队列
}

//单一缓存项
type CacheItem struct {
	Key interface{}
	Value interface{}
	Expiration int64	//过期时间 单位秒
}

//站表实例
var TbCache *TBCache

func init(){
	NewCache(1000,8000,10000)
	TbLogger.Info("初始化Cache成功")
}

//实例化一个站表对象
func NewCache(maxEntries int, dfExpiration int64,periodTime int) *TBCache {

	if maxEntries <=0 {
		fmt.Println("最大缓存数必须>0，设置默认值20")
		maxEntries = 20
	}

	if dfExpiration <= 0 {
		fmt.Println("默认缓存时间必须>0,设置默认值10")
		dfExpiration = 10
	}

	if periodTime <= 0 {
		fmt.Println("默认定时时间必须>0，设置默认值为30")
		periodTime = 30
	}


	TbCache = &TBCache{
		MaxEntries:maxEntries,
		DfExpiration:dfExpiration,
		periodTime:periodTime,
		RwLock:new(sync.RWMutex),
		Bucket:&CacheContainer{
			BucketMap:make(map[interface{}]*list.Element),
			CacheList:list.New(),
		},
		ObjectPool:&sync.Pool{
			New:func() interface{}{
				return &CacheItem{}
			},
		},
	}

	go TbCache.periodClear()  //开启定时清理现场

	return TbCache
}

//添加缓存记录-如果key已经存在，则替换覆盖原来的value
func (st *TBCache)InsertCache(key interface{},value interface{},expiration...int64){

	if st.Bucket == nil {
		TbLogger.Error("缓存容器没有初始化")
		return
	}

	SetExpiration := st.DfExpiration

	if expiration!=nil{
		SetExpiration = expiration[0]
	}

	//开启写锁
	st.RwLock.Lock()

	//key存在，覆盖原来的value
	if el,ok := st.Bucket.BucketMap[key];ok{
		cacheItem := el.Value.(*CacheItem)
		cacheItem.Value = value
		cacheItem.Expiration = SetExpiration
		st.RwLock.Unlock()
		return
	}

	var cacheItem *CacheItem
	typeAvouch := st.ObjectPool.Get()
	var ok bool

	if cacheItem,ok = typeAvouch.(*CacheItem);ok == false{  //类型断言，判断从池子中拿出来的是否为*CacheItem
		cacheItem = &CacheItem{}
	}

	cacheItem.Key = key
	cacheItem.Value = value
	cacheItem.Expiration = time.Now().Add(time.Duration(SetExpiration)*time.Microsecond).Unix()

	element := st.Bucket.CacheList.PushFront(cacheItem)  //新进缓存插入链表头
	st.Bucket.BucketMap[key] = element					//加入到map中

	if st.Bucket.CacheList.Len() > st.MaxEntries {  //判断缓存是否满了，满了删除链表末端元素
		backElement := st.Bucket.CacheList.Back()
		backItem := backElement.Value.(*CacheItem)
		st.Bucket.CacheList.Remove(backElement)
		delete(st.Bucket.BucketMap,backItem.Key)
		st.ObjectPool.Put(&backItem)
	}
	st.RwLock.Unlock()
}

//检查给定key值是否在缓存中,存在便返回Value
func (st *TBCache)GetValue(key interface{}) (interface{}) {
	if st.Bucket == nil {
		TbLogger.Info("缓存容器没有初始化")
		return nil
	}

	st.RwLock.RLock()
	defer st.RwLock.RUnlock()

	if element,ok := st.Bucket.BucketMap[key];ok{
		st.reSetLocation(element)
		return element.Value.(*CacheItem).Value
	}

	return nil

}

func (st *TBCache)IsExist(key interface{}) bool{
	if element,ok := st.Bucket.BucketMap[key];ok{
		st.reSetLocation(element)
		return true
	}
	return false
}


//删除缓存
func(st *TBCache)DeleteCache(key interface{}) bool{
	el := st.Bucket.BucketMap[key]
	if el==nil{
		return true
	}
	cacheItem,ok:= el.Value.(*CacheItem)
	if !ok {
		TbLogger.Info("断言失败")
		return false
	}
	st.Bucket.CacheList.Remove(el)
	delete(st.Bucket.BucketMap,key)
	st.ObjectPool.Put(&cacheItem)
	return true
}

//将元素调整到链表头
func (st *TBCache)reSetLocation(el *list.Element){

	cacheItem ,ok := el.Value.(*CacheItem)
	if !ok {
		TbLogger.Info("reSet断言转换失败")
		return
	}

	cacheItem.Expiration = time.Now().
		Add(time.Duration(st.DfExpiration)*time.Microsecond).Unix()  //重新设置时间

	st.Bucket.CacheList.MoveToFront(el) //调整到表头
}

//处理过期缓存
func (st *TBCache)clearTimeOut(){

	st.RwLock.Lock()

	for _,el := range st.Bucket.BucketMap{
		cacheItem ,ok := el.Value.(*CacheItem)
		if !ok {
			fmt.Println("clearTimeOut 断言转换失败")
			st.RwLock.Unlock()
			return
		}

		if time.Now().Unix() > cacheItem.Expiration {
			st.Bucket.CacheList.Remove(el)
			delete(st.Bucket.BucketMap,cacheItem.Key)
			st.ObjectPool.Put(&cacheItem)
		}
	}

	st.RwLock.Unlock()

}

//定时线程
func (st *TBCache)periodClear(){
	st.Ticker = time.NewTicker(time.Duration(st.periodTime)*time.Second)
	for{
		select {
		case <-st.Ticker.C:
			st.clearTimeOut()
		}
	}
}