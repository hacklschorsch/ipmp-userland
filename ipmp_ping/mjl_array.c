#ifdef _THREAD_SAFE
#if defined(__linux__)
#define _GNU_SOURCE
#endif
#include <pthread.h>
#endif

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "mjl_array.h"
#include <stdio.h>
#include <assert.h>

struct mjl_array
{
  /* these variables are the core of the array datastructure */
  void          **array;
  int             size;
  int             count;
  int             growby;

  /*
   * the comparison function used for keeping items in order, and
   * the sorted flag, says if the array is sorted or not
   */
  int             (*compare)(const void **a, const void **b);
  int             sorted;

  /*
   * these variables are so the array can be shared in a multithreaded
   * environment
   *
   * use mutex is a flag that specifies how we should use (or not) the mutex
   * on this array; it can have three values:
   *
   *  - zero : only one thread uses this data structure and we don't need the
   *           mutex structure.
   *
   *  - one  : we use mutexes to lock the data structure.
   */

#ifdef _THREAD_SAFE
  int             use_mutex;
  pthread_mutex_t mutex;
#endif /* _THREAD_SAFE */
};

void array_lock_internal(struct mjl_array *array)
{
#ifdef _THREAD_SAFE
  if(array->use_mutex == 1)
    {
      pthread_mutex_lock(&array->mutex);
    }
#endif /* _THREAD_SAFE */
  return;
}

void array_unlock_internal(struct mjl_array *array)
{
#ifdef _THREAD_SAFE
  if(array->use_mutex == 1)
    {
      pthread_mutex_unlock(&array->mutex);
    }
#endif /* _THREAD_SAFE */
  return;
}

#ifdef _THREAD_SAFE
int array_trylock(struct mjl_array *array)
{
  if(array->use_mutex == 0)
    {
      return 0;
    }

  if(pthread_mutex_trylock(&array->mutex) == -1)
    {
      return 0;
    }
  
  return 1;
}

int array_lock(struct mjl_array *array)
{
   if(array->use_mutex == 0)
    {
      return 0;
    }

  if(pthread_mutex_lock(&array->mutex) == -1)
    {
      return 0;
    }
  
  return 1;
}

int array_unlock(struct mjl_array *array)
{
  if(array->use_mutex == 0)
    {
      return 0;
    }

  /* 
   * try and unlock
   * if we fail, restore the data structure to what it should be
   * this is bogus really; not sure why i do it...
   */
  if(pthread_mutex_unlock(&array->mutex) == -1)
    {
      return 0;
    }
  
  return 1;
}

#endif /* _THREAD_SAFE */

/*
 * array_create
 *
 * allocate the array's data structures and return a pointer to the array
 * allocated
 */
struct mjl_array *array_create(int growby,
			       int (*compare)(const void **, const void **))
{
  struct mjl_array *array;

  if(growby < 1) return NULL;

  array        = (struct mjl_array *)malloc(sizeof(struct mjl_array));
  array->array = (void **)malloc(sizeof(void *) * growby);
  if(array->array == NULL)
    {
      free(array);
      return NULL;
    }

  array->size       = growby;
  array->growby     = growby;
  array->count      = 0;
  array->compare    = compare;
  array->sorted     = 1;

#ifdef _THREAD_SAFE
  array->use_mutex  = 0;
#endif

  return array;
}

/*
 * array_usemutexes
 *
 * tell the array to use a mutex on each operation that requires the array
 * to be locked or not
 *
 * the only failure condition is if we have a mutex that is currently in use
 * then we can't destroy it.  the only recommendation i have is to sleep() and
 * then try setting the not use flag later.
 */
#ifdef _THREAD_SAFE
int array_usemutexes(struct mjl_array *array, int useornot)
{
  pthread_mutexattr_t mattr;

  if(array == NULL) return 0;

  /*
   * if we want to use a mutex and we don't currently have that facility
   * then make a mutex
   */
  if(useornot == 1 && array->use_mutex == 0)
    {
      pthread_mutexattr_init(&mattr);
      pthread_mutexattr_settype(&mattr, PTHREAD_MUTEX_RECURSIVE);

      if(pthread_mutex_init(&array->mutex, &mattr) != 0)
	{
	  return 0;
	}

      array->use_mutex = 1;
      return 1;
    }
  /*
   * if we currently have a mutex and we don't want to use it, destroy it.
   * if we can't destroy the mutex then fail.
   */
  else if(useornot == 0 && array->use_mutex == 1)
    {
      if(pthread_mutex_destroy(&array->mutex) == 0)
	{
	  array->use_mutex = 0;
	  return 1;
	}
    }
  return 0;
}
#endif /* _THREAD_SAFE */

/*
 * array_insert
 *
 * insert the value passed into the array.
 * return the place in the array where the value goes, or -1 if the value
 * could not be inserted.
 *
 * if the array is used by more than one thread, we wait till we have
 * exclusive access and lock it.
 */
int array_insert(struct mjl_array *array, void *ptr)
{
  int    place;
  int    newsize;
  void **newarray;
  /*const void **a, **b;*/

  /* sanity check */
  if(array == NULL)
    {
      /*mjl_syslog_message("array_insert: sanity check failed");*/
      return -1;
    }

  /* if we use this array in multiple threads, lock it */
  array_lock_internal(array);

  /* if this array has run out of space make some new space  */
  if(array->count == array->size)
    {
      /* try and make some more space for the elements by realloc */
      newsize  = array->size + array->growby;
      newarray = (void **)realloc(array->array, newsize*sizeof(void *));
      if(newarray == NULL)
	{
	  array_unlock_internal(array);
	  /*mjl_syslog_message("array_insert: could not realloc space");*/
	  return -1;
	}

      /* free up the old array and put the pointers back in place */
      array->size  = newsize;
      array->array = newarray;
    }

  /* put the value into the array, and then return the place where it went */
  place = array->count;
  array->count++;
  array->array[place] = ptr;

  /*
   *if(array->compare && array->sorted)
   * {
   *   a = (const void **)&array->array[place-1];
   *   b = (const void **)&array->array[place];
   *   if(array->compare(a, b) > 0)
   *	{
   *	  array->sorted = 0;
   *	}
   * }
   */

  array_unlock_internal(array);

  /*printf("array_insert: place %d\n", place);*/
  return place;
}

/*
 * array_destroy
 *
 * free up the array and the various data structures.
 */
int array_destroy(struct mjl_array *array, void(*destroy)(void *))
{
  int i;

  if(array == NULL || array->array == NULL) return 0;

#ifdef _THREAD_SAFE
  /* try and destroy the mutex, if its locked it will fail */
  if(array->use_mutex && pthread_mutex_destroy(&array->mutex) != 0) return 0;
#endif

  /*
   * if the user has supplied a destroy function,
   * apply it to all the elements
   */
  if(destroy != NULL)
    {
      for(i=0; i<array->count; i++)
	{
	  destroy(array->array[i]);
	}
    }

  /* free the memory ! */
  free(array->array);
  free(array);

  return 1;
}

/*
 * array_compact
 *
 * shrink the amount of memory allocated if we do not use it all
 */
int array_compact(struct mjl_array *array)
{
  void **newarray;
  if(array == NULL) return 0;

  array_lock_internal(array);

  /* do we have to shrink the array? */
  if(array->count < array->size)
    {
      newarray = (void **)realloc(array->array, array->count * sizeof(void *));
      if(newarray == NULL)
	{
	  array_unlock_internal(array);
	  return 0;
	}
      array->array = newarray;
      array->size  = array->count;
    }

  array_unlock_internal(array);
  return 1;
}

/*
 * array_quicksort_using
 *
 * quicksort the array using the comparison function passed in
 */
int array_quicksort_using(struct mjl_array *array,
			  int (*compare)(const void **, const void **))
{
  if(array == NULL || compare == NULL)
    {
      return 0;
    }

  array_lock_internal(array);
  if(array->count > 1)
    {
      qsort(array->array, array->count, sizeof(void *),
	    (int (*)(const void *, const void *))compare);
    }
  array_unlock_internal(array);

  return 1;
}


/*
 * array_quicksort
 *
 * sort the array using the quicksort algorithm built into unix (or freebsd
 * at least)
 *
 * man quicksort for more information
 */
int array_quicksort(struct mjl_array *array)
{
  if(array == NULL || array->compare == NULL)
    {
      assert(array != NULL && array->compare != NULL);
      /*mjl_syslog_message("array_quicksort: sanity check");*/
      return 0;
    }

  array_lock_internal(array);
  if(array->count > 1)
    {
      /*mjl_syslog_message("array_quicksort: %d items", array->count);*/
      qsort(array->array, array->count, sizeof(void *),
	    (int (*)(const void *, const void *))array->compare);
    }
  array_unlock_internal(array);

  return 1;
}

#if defined(__FreeBSD__) || defined(__NetBSD__)
/*
 * array_heapsort
 *
 * sort the array using the heapsort algorithm built into unix (or freebsd
 * at least)
 *
 * man heapsort for more information
 */
int array_heapsort(struct mjl_array *array)
{
  int ret;

  if(array == NULL || array->compare == NULL) return 0;
  array_lock_internal(array);
  ret = heapsort(array->array, array->count, sizeof(void *),
		 (int (*)(const void *, const void *))array->compare);
  array_unlock_internal(array);

  if(ret == -1) return 0;

  return 1;
}
#endif

/*
 * array_find_internal
 *
 * look for an item, go as close as it can and then return the place where it
 * got to.  this is so we can do a findclosest and a standard find with the
 * same base code.
 *
 * the array assumes that all locking operations have been taken care of before
 * this function is called; if you don't well its your own fault.
 *
 * this function also assumes that array and ptr are valid as well.
 */
int array_find_internal(struct mjl_array *array, void *ptr,
			int (*compare)(const void **, const void **))
{
  int i, j;
  int left, right;

  /* sanity check */
  if(array->count < 1)
    {
      return -1;
    }

  /*
   * if there is only one item in the array, we got as far as "examining" this
   * item
   */
  if(array->count == 1)
    {
      return 0;
    }

  /* if the array is not sorted, we need to do this before we find anything */

  /*if(array->sorted == 0)
   * {
   *  qsort(array->array, array->count, sizeof(void *),
   *    (int (*)(const void *, const void *))array->compare);
   *  array->sorted = 1;
   *}
   */

  /*
   * init some vars; we need to set i to zero just incase left == right
   * ie there is just one item in the array and the while loop is not
   * entered.
   *
   * i is set to zero for the chance that the array has just one element
   */
  left  = 0;
  right = array->count-1;
  i     = 0;

  while(left != right)
    {
      i = (left + right) / 2;
      j = compare((const void **)&ptr, (const void **)&array->array[i]);

      if(j == 0)
	{
	  return i;
	}
      else if(j < 0) right = i;
      else           left = i+1;
    }

  return left;
}

/*
 * array_find_using
 *
 * find an item in the array, using the supplied compare function.
 * this function assumes that the contents have already been sorted
 */
void *array_find_using(mjl_array_t *array, void *ptr,
		       int (*compare)(const void **, const void **))
{
  void *ret;
  int   i;

  /* sanity checks */
  if(array == NULL || compare == NULL || ptr == NULL) return NULL;

  array_lock_internal(array);

  i = array_find_internal(array, ptr, compare);
  if(i == -1)
    {
      array_unlock_internal(array);
      return NULL;
    }

  /*printf("array_find_internal points at %d\n", i);*/
  ret = NULL;
  if(compare((const void **)&ptr, (const void **)&array->array[i]) == 0)
    {
      ret = array->array[i];
    }

  array_unlock_internal(array);
  return ret;
}

/*
 * array_find
 *
 * find an item in the array.  this function assumes that the array is sorted
 */
void *array_find(struct mjl_array *array, void *ptr)
{
  void *ret;
  int   i;

  /* sanity checks */
  if(array == NULL || array->compare == NULL || ptr == NULL) return NULL;

  array_lock_internal(array);

  i = array_find_internal(array, ptr, array->compare);
  if(i == -1)
    {
      array_unlock_internal(array);
      return NULL;
    }

  /*printf("array_find_internal points at %d\n", i);*/
  ret = NULL;
  if(array->compare((const void **)&ptr, (const void **)&array->array[i]) == 0)
    {
      ret = array->array[i];
    }

  array_unlock_internal(array);
  return ret;
}

int array_findclosest(struct mjl_array *array, void *ptr,
		      int (*close)(const void **,const void **, const void **))
{
  int          i, j;
  const void **a, **b, **c;

  /* sanity checks */
  if(array == NULL || (close == NULL && array->compare == NULL) || ptr == NULL)
    {
      return -1;
    }

  array_lock_internal(array);

  i = array_find_internal(array, ptr, array->compare);

  /*
   * if we find a valid item in the array, we still need to check further to
   * see if it is actually the closest item in the array
   */
  if(i != -1)
    {
      j = array->compare((const void **)&array->array[i], (const void **)&ptr);

      /* the item we are looking at is always the middle of the comparison */
      b = (const void **)&ptr;

      /*
       * now check to see which item is actually the closest to what we are
       * looking for.
       *
       * check the item before this one if the one we have is greater than it.
       */
      if(j < 0 && i != array->count-1)
	{
	  /* this is the item after the one we are looking at */
	  c = (const void **)&array->array[i+1];
	  if(close == NULL)
	    {
	      if(abs(array->compare(b, c)) < abs(j))
		{
		  i++;
		}
	    }
	  else
	    {
	      a = (const void **)&array->array[i];
	      if(close(a, b, c) == 1) i++;
	    }
	}
      /*
       * else check the item after this one if the one we have is less than it
       */
      else if (j > 0 && i != 0)
	{
	  a = (const void **)&array->array[i-1];
	  if(close == NULL)
	    {
	      if(abs(array->compare(a, b)) < abs(j))
		{
		  i--;
		}
	    }
	  else
	    {
	      c = (const void **)&array->array[i];
	      if(close(a, b, c) == -1) i--;
	    }
	}
    }

  array_unlock_internal(array);

  return i;
}

void *array_getitem(struct mjl_array *array, int item)
{
  void *ret;

  if(item < 0 || array == NULL)
    {
      return NULL;
    }

  /*
   * i don't think there should be a lock on this method, it is not atomic
   * (the caller knows the item number ahead of time)
   * array_lock_internal(array);
   */

  if(item >= array->count || array->array == NULL)
    {
      return NULL;
    }

  ret = array->array[item];

  return ret;
}

int array_getcount(struct mjl_array *array)
{
  if(array == NULL) return -1;
  return array->count;
}

void *array_getlastitem(struct mjl_array *array)
{
  void *ret;
  if(array == NULL)
    {
      return NULL;
    }

  array_lock_internal(array);
  if(array->array == NULL || array->count == 0)
    {
      array_unlock_internal(array);
      return NULL;
    }

  ret = array->array[array->count];
  array_unlock_internal(array);
  return ret;
}

mjl_array_t *array_splitfrom_internal(mjl_array_t *array, int to)
{
  mjl_array_t *split;
  int          bytes;

  /* sanity checks */
  if(array == NULL || to < 1)
    {
      /*printf("array_splitfromhead: failed array == NULL || %d < 1\n", to);*/
      return NULL;
    }

  /* further sanity checks */
  if(array->count < to)
    {
      /*printf("array_splitfromhead: failed array->count < to\n");*/
      return NULL;
    }

  /* allocate a new array data structure */  
  split = (mjl_array_t *)malloc(sizeof(mjl_array_t));
  if(split == NULL)
    {
      /*printf("array_splitfromhead: failed malloc of split\n");*/
      return NULL;
    }

  bzero(split, sizeof(mjl_array_t));

  bytes        = sizeof(void *) * to;
  split->array = (void **)malloc(bytes);
  if(split->array == NULL)
    {
      /*printf("array_splitfromhead: failed malloc of split->array\n");*/
      free(split);
      return NULL;
    }
  bcopy(array->array, split->array, bytes);

  array->count -= to;
  if(array->count > 0)
    {
      bcopy(&array->array[to], array->array, array->count * sizeof (void *));
    }

  split->growby     = array->growby;
  split->size       = split->count = to;
  split->sorted     = array->sorted;
  split->compare    = array->compare;

#ifdef _THREAD_SAFE
  split->use_mutex  = 0;
#endif

  return split;
}

/*
 * array_splitfromhere
 *
 * split the array at a point into two and return the items before the split
 * point 
 */
mjl_array_t *array_splitfromhere(mjl_array_t *array, void *here)
{
  mjl_array_t *split;
  int          index;
  void        *item;
  int          i;

  if(array == NULL || array->compare == NULL || here == NULL) return NULL;

  array_lock_internal(array);

  /* 
   * if there is only one item in the array, we need to figure out if that
   * item stays or goes.
   */
  if(array->count == 1)
    {
      item = array->array[0];
      i = array->compare((const void **)&here, (const void **)&item);

      if(i < 0)
	{
	  array_unlock_internal(array);
	  return NULL;
	}
      else
	{
	  index = 1;
	}
    }
  else
    {
      /*
       * find the closest value to `here'.  it will return the item to the
       * left of the item we are looking for if it does not find an exact match
       */
      index = array_find_internal(array, here, array->compare);
      if(index == -1)
	{
	  array_unlock_internal(array);
	  return NULL;
	}
    }

  /* now all we need to do is split the array at the point and we are done */
  split = array_splitfrom_internal(array, index);
  array_unlock_internal(array);

  return split;
}

void array_print(struct mjl_array *array, int (*tostr)(void *, char *, size_t))
{
  int i;
  char buf[256];

  if(array == NULL || tostr == NULL)
    {
      return;
    }

  array_lock_internal(array);
  for(i=0; i<array->count; i++)
    {
      if(tostr(array->array[i], buf, sizeof(buf)) == 1)
	{
	  printf("%s\n", buf);
	}
    }
  array_unlock_internal(array);

  return;
}

/*
 * array_merge
 *
 * join b to the end of array a
 */
int array_merge(struct mjl_array *a, struct mjl_array *b)
{
  int    newsize;
  void **newarray;

  if(a == NULL || b == NULL)
    {
      return 0;
    }

  array_lock_internal(a);

  newsize = a->count + b->count;

  if(newsize > a->size)
    {
      newarray = (void **)realloc(a->array, newsize * sizeof(void *));
      if(newarray == NULL)
	{
	  array_unlock_internal(a);
	  return 0;
	}

      a->array = newarray;
      a->size  = newsize;
    }

  bcopy(b->array, &a->array[a->count], b->count * sizeof(void *));  
  a->count = newsize;

  array_unlock_internal(a);

  return 1;
}

/*
 * array_remove
 *
 * remove a section of the array by moving the end section of the array
 * over the stuff to remove.
 */
int array_remove(struct mjl_array *array, int from, int to)
{
  if(array == NULL || from < 0 || from >= to)
    {
      /*mjl_syslog_message("array_remove: sanity check failed");*/
      return 0;
    }

  array_lock_internal(array);
  
  if(to > array->count)
    {
      /*mjl_syslog_message("array_remove: to > count");*/
      array_unlock_internal(array);
      return 0;
    }

  bcopy(array->array+to, array->array+from, (array->count-to)*sizeof(void *));

  array->count -= (to-from);
  array_unlock_internal(array);

  return 1;
}

int array_applyfunction(struct mjl_array *array, int (*function)(void *))
{
  int i;

  array_lock_internal(array);
  for(i=0; i<array->count; i++)
    {
      if(function(array->array[i]) == 0)
	{
	  array_unlock_internal(array);
	  return 0;
	}
    }
  array_unlock_internal(array);
  return 1;
}

int array_init()
{
  return 1;
}
